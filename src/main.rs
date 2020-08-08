use rusoto_core::{Region, HttpClient};
use rusoto_core::signature::SignedRequest;
use rusoto_core::param::Params;
use rusoto_ec2::{
    Ec2,
    Ec2Client,
    ImportVolumeRequest,
    DescribeConversionTasksRequest,
    DiskImageDetail,
    VolumeDetail,
    CreateSnapshotRequest,
    DescribeSnapshotsRequest,
    RegisterImageRequest,
    BlockDeviceMapping,
    EbsBlockDevice,
    DescribeImagesRequest,
};
use rusoto_s3::{
    S3,
    S3Client,
    HeadObjectRequest,
    GetObjectRequest,
    PutObjectRequest,
    DeleteObjectRequest,
};
use rusoto_s3::util::{PreSignedRequest, PreSignedRequestOption};
use rusoto_credential::{DefaultCredentialsProvider, ProvideAwsCredentials};
use anyhow::{anyhow, bail, Result};
use xml::writer::{EventWriter, EmitterConfig, XmlEvent};
use std::io::Write;
use std::time::Duration;
use std::pin::Pin;
use std::future::Future;

const BUCKET: &str = "oxide-disk-images";
const REGION: Region = Region::UsEast1;

trait EventWriterExt {
    fn simple_tag(&mut self, n: &str, v: &str) -> Result<()>;
}

fn sleep(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

impl<T: Write> EventWriterExt for EventWriter<T> {
    fn simple_tag(&mut self, n: &str, v: &str) -> Result<()> {
        self.write(XmlEvent::start_element(n))?;
        self.write(XmlEvent::characters(v))?;
        self.write(XmlEvent::end_element())?;
        Ok(())
    }
}

async fn sign_delete(c: &dyn ProvideAwsCredentials, k: &str) -> Result<String> {
    let creds = c.credentials().await?;
    Ok(DeleteObjectRequest {
        bucket: BUCKET.to_string(),
        key: k.to_string(),
        ..Default::default()
    }.get_presigned_url(&REGION, &creds, &PreSignedRequestOption {
        expires_in: Duration::from_secs(3600)
    }))
}

async fn sign_head(c: &dyn ProvideAwsCredentials, k: &str) -> Result<String> {
    let creds = c.credentials().await?;
    let uri = format!("/{}/{}", BUCKET, k);
    let mut req = SignedRequest::new("HEAD", "s3", &REGION, &uri);
    let params = Params::new();

    let expires_in = Duration::from_secs(3600);

    req.set_params(params);
    Ok(req.generate_presigned_url(&creds, &expires_in, false))
}

async fn sign_get(c: &dyn ProvideAwsCredentials, k: &str) -> Result<String> {
    let creds = c.credentials().await?;
    Ok(GetObjectRequest {
        bucket: BUCKET.to_string(),
        key: k.to_string(),
        ..Default::default()
    }.get_presigned_url(&REGION, &creds, &PreSignedRequestOption {
        expires_in: Duration::from_secs(3600)
    }))
}

struct ImageSizes {
    bytes: i64,
    gb: i64,
}

impl ImageSizes {
    fn bytes(&self) -> String {
        self.bytes.to_string()
    }

    fn end(&self) -> String {
        (self.bytes - 1).to_string()
    }

    fn gb(&self) -> String {
        self.gb.to_string()
    }
}

async fn image_size(s3: &dyn S3, k: &str) -> Result<ImageSizes> {
    /*
     * Get size of uploaded object.
     */
    let ikh = s3.head_object(HeadObjectRequest {
        bucket: BUCKET.to_string(),
        key: k.to_string(),
        ..Default::default()
    }).await?;

    /*
     * We need the size in bytes, as well as the size in GiB rounded up to the
     * next GiB (so that the created volume is large enough to contain the
     * image.
     */
    let bytes = ikh.content_length.unwrap();
    let gb = (bytes + (1 << 30) - 1) / (1 << 30);

    Ok(ImageSizes { bytes, gb })
}

async fn import_volume(s: Stuff<'_>) -> Result<()> {
    let pfx = s.args.opt_str("p").unwrap();
    let kimage = pfx.clone() + "/disk.raw";
    let kmanifest = pfx.clone() + "/manifest.xml";

    let sz = image_size(s.s3, &kimage).await?;

    /*
     * Upload raw:
     */
    let mut out = Vec::new();
    let mut w: EventWriter<&mut Vec<u8>> = EmitterConfig::new()
        .perform_indent(true)
        .create_writer(&mut out);

    w.write(XmlEvent::start_element("manifest"))?;

    w.simple_tag("version", "2010-11-15")?;
    w.simple_tag("file-format", "RAW")?;

    w.write(XmlEvent::start_element("importer"))?;
    w.simple_tag("name", "oxide-aws-import")?;
    w.simple_tag("version", "1.0.0")?;
    w.simple_tag("release", "2020-08-06")?;
    w.write(XmlEvent::end_element())?;

    w.simple_tag("self-destruct-url",
        &sign_delete(s.credprov, &kmanifest).await?)?;

    w.write(XmlEvent::start_element("import"))?;

    w.simple_tag("size", &sz.bytes())?;
    w.simple_tag("volume-size", &sz.gb())?;
    w.write(XmlEvent::start_element("parts").attr("count", "1"))?;

    w.write(XmlEvent::start_element("part").attr("index", "0"))?;
    w.write(XmlEvent::start_element("byte-range")
        .attr("start", "0")
        .attr("end", &sz.end()))?;
    w.write(XmlEvent::end_element())?; /* byte-range */
    w.simple_tag("key", &kimage)?;
    w.simple_tag("head-url", &sign_head(s.credprov, &kimage).await?)?;
    w.simple_tag("get-url", &sign_get(s.credprov, &kimage).await?)?;
    w.simple_tag("delete-url", &sign_delete(s.credprov, &kimage).await?)?;
    w.write(XmlEvent::end_element())?; /* part */

    w.write(XmlEvent::end_element())?; /* parts */
    w.write(XmlEvent::end_element())?; /* import */
    w.write(XmlEvent::end_element())?; /* manifest */

    out.write(b"\n")?;

    println!("{}", String::from_utf8(out.clone())?);

    println!("uploading -> {}", &kmanifest);

    let req = PutObjectRequest {
        bucket: BUCKET.to_string(),
        key: kmanifest.clone(),
        body: Some(out.into()),
        ..Default::default()
    };
    s.s3.put_object(req).await?;

    println!("ok!");

    println!("importing volume...");

    let availability_zone = REGION.name().to_string() + "a";
    let import_manifest_url = sign_get(s.credprov, &kmanifest).await?;
    let res = s.ec2.import_volume(ImportVolumeRequest {
        availability_zone,
        dry_run: Some(false),
        image: DiskImageDetail {
            format: "RAW".to_string(),
            import_manifest_url,
            bytes: sz.bytes,
        },
        volume: VolumeDetail {
            size: sz.gb,
        },
        description: None,
    }).await?;

    println!("res: {:#?}", res);

    let ct = if let Some(ct) = &res.conversion_task {
        ct
    } else {
        bail!("No conversion task?!");
    };

    let ctid = ct.conversion_task_id.as_deref().unwrap();
    println!("CONVERSION TASK ID: {}", ctid);

    /*
     * Wait for success!
     */
    println!("waiting for conversion task...");

    let mut volid = None;

    let cts = loop {
        let dct = DescribeConversionTasksRequest {
            conversion_task_ids: Some(vec![ctid.to_string()]),
            ..Default::default()
        };

        let res = s.ec2.describe_conversion_tasks(dct).await?;

        let mut v = res.conversion_tasks.ok_or(anyhow!("no ct"))?;

        if v.len() != 1 {
            println!("got {} tasks?!", v.len());
            sleep(5_000);
            continue;
        }

        let ct = &v[0];

        if volid.is_none() {
            if let Some(ivtd) = &ct.import_volume {
                if let Some(vol) = &ivtd.volume {
                    if let Some(id) = &vol.id {
                        if !id.trim().is_empty() {
                            println!("INFO: volume ID is {}", id);
                            volid = Some(id.to_string());
                        }
                    }
                }
            }
        }

        let mut msg = ctid.to_string() + ": ";
        msg += ct.state.as_deref().unwrap_or("<unknown state>");
        if let Some(status_message) = &ct.status_message {
            msg += ": ";
            msg += status_message;
        }

        if let Some(state) = &ct.state {
            if state != "active" && state != "pending" {
                println!("state is now \"{}\"; exiting loop", state);
                drop(ct);
                assert_eq!(v.len(), 1);
                break v.pop();
            }
        }

        println!("waiting: {}", msg);

        sleep(5_000);
    };

    println!("final state: {:#?}", cts);
    println!("conversion task ID: {:?}", ctid);
    println!("volume ID: {:?}", volid);

    Ok(())
}

async fn create_snapshot(s: Stuff<'_>) -> Result<()> {
    let volid = s.args.opt_str("v").unwrap();

    let res = s.ec2.create_snapshot(CreateSnapshotRequest {
        volume_id: volid.clone(),
        ..Default::default()
    }).await?;

    println!("res: {:#?}", res);

    let snapid = res.snapshot_id.unwrap();
    println!("SNAPSHOT ID: {}", snapid);

    loop {
        let res = s.ec2.describe_snapshots(DescribeSnapshotsRequest {
            snapshot_ids: Some(vec![snapid.clone()]),
            ..Default::default()
        }).await?;

        let snapshots = res.snapshots.as_ref().unwrap();

        if snapshots.len() != 1 {
            println!("got {} snapshots?!", snapshots.len());
            sleep(5_000);
            continue;
        }
        let snap = &snapshots[0];

        println!("snapshot state: {:#?}", snap);

        if snap.state.as_deref().unwrap() == "completed" {
            println!("COMPLETED SNAPSHOT ID: {}", snapid);
            break;
        }

        sleep(5_000);
    }

    Ok(())
}

fn ss(s: &str) -> Option<String> {
    Some(s.to_string())
}

async fn register_image(s: Stuff<'_>) -> Result<()> {
    let name = s.args.opt_str("n").unwrap();
    let snapid = s.args.opt_str("s").unwrap();

    let res = s.ec2.describe_snapshots(DescribeSnapshotsRequest {
        snapshot_ids: Some(vec![snapid.clone()]),
        ..Default::default()
    }).await?;
    let snap = res.snapshots.unwrap().get(0).unwrap().clone();

    let res = s.ec2.register_image(RegisterImageRequest {
        name: name.clone(),
        root_device_name: ss("/dev/sda1"),
        virtualization_type: ss("hvm"),
        architecture: ss("x86_64"),
        ena_support: Some(false),
        block_device_mappings: Some(vec![
            BlockDeviceMapping {
                device_name: ss("/dev/sda1"), /* XXX? */
                ebs: Some(EbsBlockDevice {
                    snapshot_id: Some(snapid.clone()),
                    volume_type: ss("gp2"), /* XXX? */
                    volume_size: snap.volume_size,
                    ..Default::default()
                }),
                ..Default::default()
            },
            BlockDeviceMapping {
                device_name: ss("/dev/sdb"), /* XXX? */
                virtual_name: ss("ephemeral0"), /* XXX? */
                ..Default::default()
            },
            BlockDeviceMapping {
                device_name: ss("/dev/sdc"), /* XXX? */
                virtual_name: ss("ephemeral1"), /* XXX? */
                ..Default::default()
            },
            BlockDeviceMapping {
                device_name: ss("/dev/sdd"), /* XXX? */
                virtual_name: ss("ephemeral2"), /* XXX? */
                ..Default::default()
            },
            BlockDeviceMapping {
                device_name: ss("/dev/sde"), /* XXX? */
                virtual_name: ss("ephemeral3"), /* XXX? */
                ..Default::default()
            },
        ]),
        ..Default::default()
    }).await?;

    println!("res: {:#?}", res);

    let imageid = res.image_id.unwrap();
    println!("IMAGE ID: {}", snapid);

    loop {
        let res = s.ec2.describe_images(DescribeImagesRequest {
            image_ids: Some(vec![imageid.clone()]),
            ..Default::default()
        }).await?;

        let images = res.images.as_ref().unwrap();

        if images.len() != 1 {
            println!("got {} images?!", images.len());
            sleep(5_000);
            continue;
        }
        let image = &images[0];

        println!("image state: {:#?}", image);

        if image.state.as_deref().unwrap() == "available" {
            println!("COMPLETED IMAGE ID: {}", imageid);
            break;
        }

        sleep(5_000);
    }

    Ok(())
}

struct Stuff<'a> {
    s3: &'a dyn S3,
    ec2: &'a dyn Ec2,
    credprov: &'a DefaultCredentialsProvider,
    args: &'a getopts::Matches,
}

type Caller<'a> = fn(Stuff<'a>)
    -> Pin<Box<(dyn Future<Output = Result<()>> + 'a)>>;

#[tokio::main]
async fn main() -> Result<()> {
    let credprov = DefaultCredentialsProvider::new()?;
    let s3 = S3Client::new_with(HttpClient::new()?, credprov.clone(), REGION);
    let ec2 = Ec2Client::new_with(HttpClient::new()?, credprov.clone(), REGION);

    let mut opts = getopts::Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);

    let f: Caller = match std::env::args().skip(1).next().as_deref() {
        Some("import-volume") => {
            opts.reqopt("p", "prefix", "S3 prefix", "PREFIX");

            |s| Box::pin(import_volume(s))
        }
        Some("create-snapshot") => {
            opts.reqopt("v", "volume", "volume ID to snapshot", "VOLUME_ID");

            |s| Box::pin(create_snapshot(s))
        }
        Some("register-image") => {
            opts.reqopt("s", "snapshot", "snapshot ID to register",
                "SNAPSHOT_ID");
            opts.reqopt("n", "name", "target image name", "NAME");

            |s| Box::pin(register_image(s))
        }
        cmd => bail!("invalid command {:?}", cmd),
    };

    let args = opts.parse(std::env::args().skip(2))?;

    f(Stuff {
        s3: &s3,
        ec2: &ec2,
        credprov: &credprov,
        args: &args,
    }).await?;

    Ok(())
}

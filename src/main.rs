use rusoto_core::{Region, HttpClient};
use rusoto_core::signature::SignedRequest;
use rusoto_core::param::Params;
use rusoto_ec2 as ec2;
use ec2::{
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
    Tag,
};
use rusoto_s3 as s3;
use s3::{
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

mod table;
use table::{TableBuilder, Row};

const S3_REGION: Region = Region::UsWest2;
const EC2_REGION: Region = Region::UsWest2;

trait RowExt {
    fn add_stror(&mut self, n: &str, v: &Option<String>, def: &str);
}

impl RowExt for Row {
    fn add_stror(&mut self, n: &str, v: &Option<String>, def: &str) {
        self.add_str(n, v.as_deref().unwrap_or(def));
    }
}

trait TagExtractor {
    fn tag(&self, n: &str) -> Option<String>;
}

impl TagExtractor for Option<Vec<Tag>> {
    fn tag(&self, n: &str) -> Option<String> {
        if let Some(tags) = self.as_ref() {
            for tag in tags.iter() {
                if let Some(k) = tag.key.as_deref() {
                    if k == n {
                        return tag.value.clone();
                    }
                }
            }
        }

        None
    }
}

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

async fn sign_delete(c: &dyn ProvideAwsCredentials, b: &str, k: &str)
    -> Result<String>
{
    let creds = c.credentials().await?;
    Ok(DeleteObjectRequest {
        bucket: b.to_string(),
        key: k.to_string(),
        ..Default::default()
    }.get_presigned_url(&S3_REGION, &creds, &PreSignedRequestOption {
        expires_in: Duration::from_secs(3600)
    }))
}

async fn sign_head(c: &dyn ProvideAwsCredentials, b: &str, k: &str)
    -> Result<String>
{
    let creds = c.credentials().await?;
    let uri = format!("/{}/{}", b, k);
    let mut req = SignedRequest::new("HEAD", "s3", &S3_REGION, &uri);
    let params = Params::new();

    let expires_in = Duration::from_secs(3600);

    req.set_params(params);
    Ok(req.generate_presigned_url(&creds, &expires_in, false))
}

async fn sign_get(c: &dyn ProvideAwsCredentials, b: &str, k: &str)
    -> Result<String>
{
    let creds = c.credentials().await?;
    Ok(GetObjectRequest {
        bucket: b.to_string(),
        key: k.to_string(),
        ..Default::default()
    }.get_presigned_url(&S3_REGION, &creds, &PreSignedRequestOption {
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

async fn image_size(s3: &dyn S3, b: &str, k: &str) -> Result<ImageSizes> {
    /*
     * Get size of uploaded object.
     */
    let ikh = s3.head_object(HeadObjectRequest {
        bucket: b.to_string(),
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
    let bucket = s.args.opt_str("b").unwrap();
    let kimage = pfx.clone() + "/disk.raw";
    let kmanifest = pfx.clone() + "/manifest.xml";

    let volid = i_import_volume(s, &bucket, &kimage, &kmanifest).await?;
    println!("COMPLETED VOLUME ID: {}", volid);

    Ok(())
}

async fn i_import_volume(s: Stuff<'_>, bkt: &str, kimage: &str, kmanifest: &str)
    -> Result<String>
{
    let sz = image_size(s.s3, bkt, kimage).await?;

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
        &sign_delete(s.credprov, bkt, kmanifest).await?)?;

    w.write(XmlEvent::start_element("import"))?;

    w.simple_tag("size", &sz.bytes())?;
    w.simple_tag("volume-size", &sz.gb())?;
    w.write(XmlEvent::start_element("parts").attr("count", "1"))?;

    w.write(XmlEvent::start_element("part").attr("index", "0"))?;
    w.write(XmlEvent::start_element("byte-range")
        .attr("start", "0")
        .attr("end", &sz.end()))?;
    w.write(XmlEvent::end_element())?; /* byte-range */
    w.simple_tag("key", kimage)?;
    w.simple_tag("head-url", &sign_head(s.credprov, bkt, kimage).await?)?;
    w.simple_tag("get-url", &sign_get(s.credprov, bkt, kimage).await?)?;
    w.simple_tag("delete-url", &sign_delete(s.credprov, bkt, kimage).await?)?;
    w.write(XmlEvent::end_element())?; /* part */

    w.write(XmlEvent::end_element())?; /* parts */
    w.write(XmlEvent::end_element())?; /* import */
    w.write(XmlEvent::end_element())?; /* manifest */

    out.write(b"\n")?;

    println!("{}", String::from_utf8(out.clone())?);

    println!("uploading -> {}", kmanifest);

    let req = PutObjectRequest {
        bucket: bkt.to_string(),
        key: kmanifest.to_string(),
        body: Some(out.into()),
        ..Default::default()
    };
    s.s3.put_object(req).await?;

    println!("ok!");

    println!("importing volume...");

    let availability_zone = EC2_REGION.name().to_string() + "a";
    let import_manifest_url = sign_get(s.credprov, bkt, &kmanifest).await?;
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

    if volid.is_none() {
        bail!("completed, but no volume ID?! {:#?}", cts);
    }

    Ok(volid.unwrap())
}

async fn create_snapshot(s: Stuff<'_>) -> Result<()> {
    let volid = s.args.opt_str("v").unwrap();

    let snapid = i_create_snapshot(s, &volid).await?;
    println!("COMPLETED SNAPSHOT ID: {}", snapid);

    Ok(())
}

async fn i_create_snapshot(s: Stuff<'_>, volid: &str) -> Result<String> {
    let res = s.ec2.create_snapshot(CreateSnapshotRequest {
        volume_id: volid.to_string(),
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

        let state = snap.state.as_deref().unwrap().to_string();

        let mut msg = snapid.to_string() + ": " + &state;
        if let Some(extra) = &snap.state_message {
            msg += ": ";
            msg += extra;
        }
        if let Some(extra) = &snap.progress {
            msg += ": progress ";
            msg += extra;
        }

        // println!("snapshot state: {:#?}", snap);

        if &state == "completed" {
            return Ok(snapid);
        }

        println!("waiting: {}", msg);

        sleep(5_000);
    }
}

fn ss(s: &str) -> Option<String> {
    Some(s.to_string())
}

async fn everything(s: Stuff<'_>) -> Result<()> {
    let name = s.args.opt_str("n").unwrap();
    let pfx = s.args.opt_str("p").unwrap();
    let bucket = s.args.opt_str("b").unwrap();
    let support_ena = s.args.opt_present("E");

    let kimage = pfx.clone() + "/disk.raw";
    let kmanifest = pfx.clone() + "/manifest.xml";

    let volid = i_import_volume(s, &bucket, &kimage, &kmanifest).await?;
    println!("COMPLETED VOLUME ID: {}", volid);

    let snapid = i_create_snapshot(s, &volid).await?;
    println!("COMPLETED SNAPSHOT ID: {}", snapid);

    let ami = i_register_image(s, &name, &snapid, support_ena).await?;
    println!("COMPLETED IMAGE ID: {}", ami);

    Ok(())
}

#[derive(Debug)]
struct Attach {
    state: String,
    instance_id: String,
}

#[derive(Debug)]
struct Volume {
    name: String,
    id: String,
    state: String,
    attach: Option<Attach>,
}

#[derive(Debug, Clone)]
enum VolumeLookup {
    ById(String),
    ByName(String),
}

#[derive(Debug)]
struct Instance {
    name: Option<String>,
    id: String,
    ip: Option<String>,
    state: String,
    launch: String,
}

#[derive(Debug, Clone)]
enum InstanceLookup {
    ById(String),
    ByName(String),
}

async fn detach_volume(s: &Stuff<'_>, id: &str) -> Result<()> {
    let lookup = VolumeLookup::ById(id.to_string());

    println!("detaching volume {}...", id);

    let mut detached = false;

    loop {
        let vol = get_volume(s, lookup.clone()).await?;

        println!("    state: {}", vol.state);
        if vol.state == "available" {
            println!("volume now available!");
            return Ok(());
        }

        if let Some(a) = &vol.attach {
            println!("    attach: {:?}", a);

            if !detached {
                let res = s.ec2.detach_volume(ec2::DetachVolumeRequest {
                    volume_id: vol.id.clone(),
                    ..Default::default()
                }).await?;

                println!("    {:#?}", res);
                detached = true;
            }
        }

        sleep(1000);
    }
}

async fn start_instance(s: &Stuff<'_>, id: &str) -> Result<()> {
    let lookup = InstanceLookup::ById(id.to_string());

    println!("starting instance {}...", id);

    let mut started = false;

    loop {
        let inst = get_instance(s, lookup.clone()).await?;

        let shouldstart = match inst.state.as_str() {
            "terminated" => {
                bail!("cannot start a terminated instance?");
            }
            n @ "running" => {
                println!("    state is {}; done!", n);
                return Ok(());
            }
            n => {
                println!("    state is {}", n);
                n == "stopped"
            }
        };

        if shouldstart && !started {
            println!("    starting...");
            let res = s.ec2.start_instances(ec2::StartInstancesRequest {
                instance_ids: vec![id.to_string()],
                ..Default::default()
            }).await?;
            println!("    {:#?}", res);
            started = true;
        }

        sleep(1000);
    }
}

async fn stop_instance(s: &Stuff<'_>, id: &str) -> Result<()> {
    let lookup = InstanceLookup::ById(id.to_string());

    println!("stopping instance {}...", id);

    let mut stopped = false;

    loop {
        let inst = get_instance(s, lookup.clone()).await?;

        let shouldstop = match inst.state.as_str() {
            n @ "stopped" => {
                println!("    state is {}; done!", n);
                return Ok(());
            }
            n => {
                println!("    state is {}", n);
                n == "running"
            }
        };

        if shouldstop && !stopped {
            println!("    stopping...");
            let res = s.ec2.stop_instances(ec2::StopInstancesRequest {
                instance_ids: vec![id.to_string()],
                ..Default::default()
            }).await?;
            println!("    {:#?}", res);
            stopped = true;
        }

        sleep(1000);
    }
}

async fn get_volume(s: &Stuff<'_>, lookup: VolumeLookup)
    -> Result<Volume>
{
    let filters = match &lookup {
        VolumeLookup::ById(id) => Some(vec![
            ec2::Filter {
                name: Some("volume-id".into()),
                values: Some(vec![id.into()]),
            },
        ]),
        VolumeLookup::ByName(name) => Some(vec![
            ec2::Filter {
                name: Some("tag:Name".into()),
                values: Some(vec![name.into()]),
            },
        ]),
    };

    let res = s.ec2.describe_volumes(ec2::DescribeVolumesRequest {
        filters,
        ..Default::default()
    }).await?;

    let mut out: Vec<Volume> = Vec::new();

    for vol in res.volumes.as_ref().unwrap_or(&vec![]).iter() {
        /*
         * Find the name tag value:
         */
        let tags = vol.tags.as_ref().unwrap();
        let nametag = tags.iter()
            .find(|t| t.key.as_deref() == Some("Name"))
            .and_then(|t| t.value.as_deref());

        let mat = match &lookup {
            VolumeLookup::ById(id) => {
                &id.as_str() == &vol.volume_id.as_deref().unwrap()
            }
            VolumeLookup::ByName(name) => {
                Some(name.as_str()) == nametag
            }
        };

        if mat {
            /*
             * Check into the attach state.
             */
            let attach = if let Some(att) = vol.attachments.as_ref() {
                if att.len() > 1 {
                    bail!("matching volume has {} attachments: {:#?}",
                        att.len(), vol);
                } else if att.len() == 1 {
                    let a = att.get(0).unwrap();
                    Some(Attach {
                        state: a.state.as_deref().unwrap().to_string(),
                        instance_id: a.instance_id.as_deref()
                            .unwrap().to_string(),
                    })
                } else {
                    None
                }
            } else {
                None
            };

            out.push(Volume {
                name: nametag.unwrap().to_string(),
                id: vol.volume_id.as_deref().unwrap().to_string(),
                state: vol.state.as_deref().unwrap().to_string(),
                attach,
            });
        }
    }

    if out.is_empty() {
        bail!("could not find volume to match {:?}", lookup);
    }

    if out.len() > 1 {
        bail!("found too many volumes that match {:?}: {:#?}", lookup, out);
    }

    Ok(out.pop().unwrap())
}

async fn get_instance(s: &Stuff<'_>, lookup: InstanceLookup)
    -> Result<Instance>
{
    let filters = match &lookup {
        InstanceLookup::ById(id) => Some(vec![
            ec2::Filter {
                name: Some("instance-id".into()),
                values: Some(vec![id.into()]),
            },
        ]),
        InstanceLookup::ByName(name) => Some(vec![
            ec2::Filter {
                name: Some("tag:Name".into()),
                values: Some(vec![name.into()]),
            },
        ]),
    };

    let res = s.ec2.describe_instances(ec2::DescribeInstancesRequest {
        filters,
        ..Default::default()
    }).await?;

    let mut out: Vec<Instance> = Vec::new();

    for res in res.reservations.as_ref().unwrap_or(&vec![]).iter() {
        for inst in res.instances.as_ref().unwrap_or(&vec![]).iter() {
            /*
             * Find the name tag value:
             */
            let nametag = inst.tags.tag("Name");

            let mat = match &lookup {
                InstanceLookup::ById(id) => {
                    &id.as_str() == &inst.instance_id.as_deref().unwrap()
                }
                InstanceLookup::ByName(name) => {
                    Some(name.as_str()) == nametag.as_deref()
                }
            };

            if mat {
                out.push(Instance {
                    name: nametag,
                    id: inst.instance_id.as_deref().unwrap().to_string(),
                    ip: inst.public_ip_address.clone(),
                    state: inst.state.as_ref().unwrap()
                        .name.as_deref().unwrap().to_string(),
                    launch: inst.launch_time.as_deref().unwrap().to_string(),
                });
            }
        }
    }

    if out.is_empty() {
        bail!("could not find instance to match {:?}", lookup);
    }

    if out.len() > 1 {
        bail!("found too many instances that match {:?}: {:#?}", lookup, out);
    }

    Ok(out.pop().unwrap())
}

async fn snapshots(s: Stuff<'_>) -> Result<()> {
    let mut t = TableBuilder::new()
        .add_column("id", 22)
        .add_column("start", 24)
        .add_column("state", 10)
        .add_column("size", 5)
        .add_column("volume", 22)
        .add_column("desc", 30)
        .output_from_list(Some("id,start,size,state,desc"))
        .output_from_list(s.args.opt_str("o").as_deref())
        .sort_from_list_desc(Some("start"))
        .sort_from_list_asc(s.args.opt_str("s").as_deref())
        .sort_from_list_desc(s.args.opt_str("S").as_deref())
        .disable_header(s.args.opt_present("H"))
        .build();

    let res = s.ec2.describe_snapshots(ec2::DescribeSnapshotsRequest {
        owner_ids: Some(vec!["self".to_string()]),
        ..Default::default()
    }).await?;

    let x = Vec::new();
    for s in res.snapshots.as_ref().unwrap_or(&x) {
        let mut r = Row::new();

        r.add_stror("id", &s.snapshot_id, "?");
        r.add_stror("start", &s.start_time, "-");
        r.add_stror("state", &s.state, "-");
        r.add_u64("size", s.volume_size.unwrap_or(0) as u64);
        r.add_stror("volume", &s.volume_id, "-");
        r.add_stror("desc", &s.description, "-");

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn volumes(s: Stuff<'_>) -> Result<()> {
    let mut t = TableBuilder::new()
        .add_column("id", 21)
        .add_column("state", 10)
        .add_column("size", 5)
        .add_column("snapshot", 22)
        .add_column("name", 24)
        .add_column("info", 30)
        .add_column("creation", 24)
        .add_column("az", 12)
        .add_column("natt", 4) /* Number of attachments */
        .output_from_list(Some("id,state,natt,info"))
        .output_from_list(s.args.opt_str("o").as_deref())
        .sort_from_list_desc(Some("creation"))
        .sort_from_list_asc(s.args.opt_str("s").as_deref())
        .sort_from_list_desc(s.args.opt_str("S").as_deref())
        .disable_header(s.args.opt_present("H"))
        .build();

    let res = s.ec2.describe_volumes(ec2::DescribeVolumesRequest {
        ..Default::default()
    }).await?;

    let x = Vec::new();
    for v in res.volumes.as_ref().unwrap_or(&x) {
        let mut r = Row::new();

        /*
         * The magic INFO column contains information we were able to glean by
         * looking further afield.
         */
        let atts = v.attachments.as_ref().unwrap();
        let info = if atts.len() != 1 {
            v.tags.tag("Name").as_deref().unwrap_or("-").to_string()
        } else {
            let a = atts.iter().next().unwrap();

            if let Some(aid) = a.instance_id.as_deref() {
                let ai = get_instance(&s,
                    InstanceLookup::ById(aid.to_string())).await?;

                if let Some(n) = ai.name.as_deref() {
                    format!("A: {}", n)
                } else {
                    format!("A: {}", aid)
                }
            } else {
                v.tags.tag("Name").as_deref().unwrap_or("-").to_string()
            }
        };

        r.add_stror("id", &v.volume_id, "?");
        r.add_str("info", &info);
        r.add_stror("state", &v.state, "-");
        r.add_u64("size", v.size.unwrap_or(0) as u64);
        r.add_stror("snapshot", &v.snapshot_id, "-");
        r.add_stror("name", &v.tags.tag("Name"), "-");
        r.add_stror("creation", &v.create_time, "-");
        r.add_stror("az", &v.availability_zone, "-");
        r.add_u64("natt", atts.len() as u64);

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}


async fn images(s: Stuff<'_>) -> Result<()> {
    let mut t = TableBuilder::new()
        .add_column("id", 21)
        .add_column("name", 24)
        .add_column("creation", 24)
        .add_column("snapshots", 22)
        .output_from_list(Some("id,name,creation"))
        .output_from_list(s.args.opt_str("o").as_deref())
        .sort_from_list_desc(Some("creation"))
        .sort_from_list_asc(s.args.opt_str("s").as_deref())
        .sort_from_list_desc(s.args.opt_str("S").as_deref())
        .disable_header(s.args.opt_present("H"))
        .build();

    let res = s.ec2.describe_images(ec2::DescribeImagesRequest {
        owners: Some(vec!["self".to_string()]),
        ..Default::default()
    }).await?;

    let x = Vec::new();
    for i in res.images.as_ref().unwrap_or(&x) {
        let mut r = Row::new();

        /*
         * If we know which snapshot ID this image is based on, render it in
         * the SNAPSHOTS column:
         */
        let snap = if let Some(bdm) = i.block_device_mappings.as_ref() {
            let mut snaps: Vec<String> = Vec::new();
            for bdm in bdm.iter() {
                if let Some(ebs) = bdm.ebs.as_ref() {
                    if let Some(sid) = ebs.snapshot_id.as_ref() {
                        snaps.push(sid.to_string());
                    }
                }
            }
            if snaps.is_empty() {
                "-".to_string()
            } else {
                snaps.sort();
                snaps.join(",")
            }
        } else {
            "-".to_string()
        };

        r.add_str("id", i.image_id.as_deref().unwrap());
        r.add_str("name", i.name.as_deref().unwrap_or("?"));
        r.add_str("creation", i.creation_date.as_deref().unwrap_or("-"));
        r.add_str("snapshots", &snap);

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn info(s: Stuff<'_>) -> Result<()> {
    let mut t = TableBuilder::new()
        .add_column("id", 19)
        .add_column("name", 28)
        .add_column("launch", 24)
        .add_column("ip", 15)
        .add_column("state", 16)
        .output_from_list(Some("id,name,ip,state"))
        .output_from_list(s.args.opt_str("o").as_deref())
        .sort_from_list_desc(Some("launch"))
        .sort_from_list_asc(s.args.opt_str("s").as_deref())
        .sort_from_list_desc(s.args.opt_str("S").as_deref())
        .disable_header(s.args.opt_present("H"))
        .build();

    if !s.args.free.is_empty() {
        for n in s.args.free.iter() {
            let i = get_instance(&s, InstanceLookup::ByName(n.to_string()))
                .await?;

            let mut r = Row::new();
            r.add_str("id", &i.id);
            r.add_stror("name", &i.name, "-");
            r.add_str("launch", &i.launch);
            r.add_stror("ip", &i.ip, "-");
            r.add_str("state", &i.state);
            t.add_row(r);
        }
    } else {
        let res = s.ec2.describe_instances(ec2::DescribeInstancesRequest {
            ..Default::default()
        }).await?;

        if let Some(r) = &res.reservations {
            for r in r.iter() {
                if let Some(i) = &r.instances {
                    for i in i.iter() {
                        let mut r = Row::new();

                        r.add_str("id", i.instance_id.as_deref().unwrap());
                        r.add_stror("name", &i.tags.tag("Name"), "-");
                        r.add_str("launch", i.launch_time.as_deref().unwrap());
                        r.add_str("ip",
                            i.public_ip_address.as_deref().unwrap_or("-"));
                        r.add_str("state", i.state.as_ref().unwrap()
                            .name.as_deref().unwrap());

                        t.add_row(r);
                    }
                }
            }
        }
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn start(s: Stuff<'_>) -> Result<()> {
    if s.args.free.len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance(&s,
        InstanceLookup::ByName(s.args.free.get(0).unwrap().to_string()))
        .await?;

    println!("starting instance: {:?}", i);

    start_instance(&s, &i.id).await?;

    println!("all done!");

    Ok(())
}

async fn stop(s: Stuff<'_>) -> Result<()> {
    if s.args.free.len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance(&s,
        InstanceLookup::ByName(s.args.free.get(0).unwrap().to_string()))
        .await?;

    println!("stopping instance: {:?}", i);

    stop_instance(&s, &i.id).await?;

    println!("all done!");

    Ok(())
}

async fn melbourne(s: Stuff<'_>) -> Result<()> {
    let target = s.args.opt_str("t").unwrap();

    let i_melbourne = get_instance(&s,
        InstanceLookup::ByName("melbourne".to_string())).await?;
    let i_watson = get_instance(&s,
        InstanceLookup::ByName("watson".to_string())).await?;
    let v_melbourne = get_volume(&s,
        VolumeLookup::ByName("melbourne".to_string())).await?;

    if i_melbourne.name.is_none() || i_watson.name.is_none() {
        bail!("instances must have names for this to work");
    }

    println!("melbourne: {:?}", i_melbourne);
    println!("watson: {:?}", i_watson);
    println!("volume: {:?}", v_melbourne);

    if let Some(a) = &v_melbourne.attach {
        if a.instance_id == i_melbourne.id {
            if target == i_melbourne.name.as_deref().unwrap() {
                println!("already attached to melbourne!");
                return Ok(());
            }

            println!("need to stop melbourne");
            stop_instance(&s, &i_melbourne.id).await?;

            println!("need to detach volume from melbourne");
            detach_volume(&s, &v_melbourne.id).await?;

        } else if a.instance_id == i_watson.id {
            if target == i_watson.name.as_deref().unwrap() {
                println!("already attached to watson!");
                return Ok(());
            } else {
                println!("need to detach from watson");
                detach_volume(&s, &v_melbourne.id).await?;
            }
        }
    } else {
        println!("not attached at all!");
    }

    /*
     * Attach the volume to the expected target!
     */
    let avr = if target == "watson" {
        ec2::AttachVolumeRequest {
            device: "/dev/sdf".into(),
            instance_id: i_watson.id.clone(),
            volume_id: v_melbourne.id.clone(),
            ..Default::default()
        }
    } else if target == "melbourne" {
        ec2::AttachVolumeRequest {
            device: "/dev/sda1".into(),
            instance_id: i_melbourne.id.clone(),
            volume_id: v_melbourne.id.clone(),
            ..Default::default()
        }
    } else {
        bail!("unexpected target: {}", target);
    };

    let res = s.ec2.attach_volume(avr).await?;
    println!("attach result: {:#?}", res);

    loop {
        let vol = get_volume(&s, VolumeLookup::ById(v_melbourne.id.clone()))
            .await?;

        println!("{:?}", vol);

        if let Some(a) = &vol.attach {
            if a.state == "attached" && vol.state == "in-use" {
                println!("all done, attached to {}!", target);
                return Ok(());
            }
        }

        sleep(1000);
    }
}

async fn register_image(s: Stuff<'_>) -> Result<()> {
    let name = s.args.opt_str("n").unwrap();
    let snapid = s.args.opt_str("s").unwrap();
    let support_ena = s.args.opt_present("E");

    let imageid = i_register_image(s, &name, &snapid, support_ena).await?;
    println!("COMPLETED IMAGE ID: {}", imageid);

    Ok(())
}

async fn i_register_image(s: Stuff<'_>, name: &str, snapid: &str, ena: bool)
    -> Result<String>
{
    let res = s.ec2.describe_snapshots(DescribeSnapshotsRequest {
        snapshot_ids: Some(vec![snapid.to_string()]),
        ..Default::default()
    }).await?;
    let snap = res.snapshots.unwrap().get(0).unwrap().clone();

    let res = s.ec2.register_image(RegisterImageRequest {
        name: name.to_string(),
        root_device_name: ss("/dev/sda1"),
        virtualization_type: ss("hvm"),
        architecture: ss("x86_64"),
        ena_support: Some(ena),
        block_device_mappings: Some(vec![
            BlockDeviceMapping {
                device_name: ss("/dev/sda1"), /* XXX? */
                ebs: Some(EbsBlockDevice {
                    snapshot_id: Some(snapid.to_string()),
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
            image_ids: Some(vec![imageid.to_string()]),
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
            return Ok(imageid);
        }

        sleep(5_000);
    }
}

#[derive(Copy, Clone)]
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
    let s3 = S3Client::new_with(HttpClient::new()?, credprov.clone(),
        S3_REGION);
    let ec2 = Ec2Client::new_with(HttpClient::new()?, credprov.clone(),
        EC2_REGION);

    let mut opts = getopts::Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);

    fn tabular(opts: &mut getopts::Options) {
        opts.optopt("s", "", "sort by columns (ascending)", "COLUMN,...");
        opts.optopt("S", "", "sort by columns (descending)", "COLUMN,...");
        opts.optopt("o", "", "select columns to display", "COLUMN,...");
        opts.optflag("H", "", "omit header");
    }

    let f: Caller = match std::env::args().skip(1).next().as_deref() {
        Some("start") => {
            |s| Box::pin(start(s))
        }
        Some("stop") => {
            |s| Box::pin(stop(s))
        }
        Some("info") => {
            tabular(&mut opts);

            |s| Box::pin(info(s))
        }
        Some("volumes") => {
            tabular(&mut opts);

            |s| Box::pin(volumes(s))
        }
        Some("snapshots") => {
            tabular(&mut opts);

            |s| Box::pin(snapshots(s))
        }
        Some("images") => {
            tabular(&mut opts);

            |s| Box::pin(images(s))
        }
        Some("melbourne") => {
            opts.reqopt("t", "target", "target VM name", "NAME");

            |s| Box::pin(melbourne(s))
        }
        Some("everything") => {
            opts.reqopt("b", "bucket", "S3 bucket", "BUCKET");
            opts.reqopt("p", "prefix", "S3 prefix", "PREFIX");
            opts.reqopt("n", "name", "target image name", "NAME");
            opts.optflag("E", "ena", "enable ENA support");

            |s| Box::pin(everything(s))
        }
        Some("import-volume") => {
            opts.reqopt("b", "bucket", "S3 bucket", "BUCKET");
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
            opts.optflag("E", "ena", "enable ENA support");

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

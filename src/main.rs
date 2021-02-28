/*
 * Copyright 2021 Oxide Computer Company
 */

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
    RunInstancesRequest,
    TagSpecification,
    InstanceNetworkInterfaceSpecification,
};
use rusoto_s3 as s3;
use s3::{
    S3,
    S3Client,
    HeadObjectRequest,
    GetObjectRequest,
    PutObjectRequest,
    DeleteObjectRequest,
    UploadPartRequest,
    CreateMultipartUploadRequest,
    CompleteMultipartUploadRequest,
    CompletedMultipartUpload,
    CompletedPart,
};
use rusoto_s3::util::{PreSignedRequest, PreSignedRequestOption};
use rusoto_credential::{
    EnvironmentProvider,
    DefaultCredentialsProvider,
    ProvideAwsCredentials
};
use anyhow::{anyhow, bail, Result, Context};
use xml::writer::{EventWriter, EmitterConfig, XmlEvent};
use std::io::{Read, Write};
use std::time::Duration;
use std::pin::Pin;
use std::future::Future;
use std::fs::File;
use std::collections::HashMap;
use bytes::BytesMut;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::str::FromStr;

mod table;
use table::{TableBuilder, Row};

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

async fn sign_delete(c: &dyn ProvideAwsCredentials, r: &Region, b: &str,
    k: &str)
    -> Result<String>
{
    let creds = c.credentials().await?;
    Ok(DeleteObjectRequest {
        bucket: b.to_string(),
        key: k.to_string(),
        ..Default::default()
    }.get_presigned_url(r, &creds, &PreSignedRequestOption {
        expires_in: Duration::from_secs(3600)
    }))
}

async fn sign_head(c: &dyn ProvideAwsCredentials, r: &Region, b: &str, k: &str)
    -> Result<String>
{
    let creds = c.credentials().await?;
    let uri = format!("/{}/{}", b, k);
    let mut req = SignedRequest::new("HEAD", "s3", r, &uri);
    let params = Params::new();

    let expires_in = Duration::from_secs(3600);

    req.set_params(params);
    Ok(req.generate_presigned_url(&creds, &expires_in, false))
}

async fn sign_get(c: &dyn ProvideAwsCredentials, r: &Region, b: &str, k: &str)
    -> Result<String>
{
    let creds = c.credentials().await?;
    Ok(GetObjectRequest {
        bucket: b.to_string(),
        key: k.to_string(),
        ..Default::default()
    }.get_presigned_url(r, &creds, &PreSignedRequestOption {
        expires_in: Duration::from_secs(300)
    }))
}

async fn put_object(s: Stuff<'_>) -> Result<()> {
    let bucket = s.args.opt_str("b").unwrap();
    let object = s.args.opt_str("o").unwrap();
    let file = s.args.opt_str("f").unwrap();

    i_put_object(s, &bucket, &object, &file).await?;
    Ok(())
}

async fn i_put_object(s: Stuff<'_>, bucket: &str, object: &str, file: &str)
    -> Result<()>
{
    let mut f = File::open(&file)?;

    let res = s.s3.create_multipart_upload(CreateMultipartUploadRequest {
        bucket: bucket.to_string(),
        key: object.to_string(),
        ..Default::default()
    }).await?;
    let upload_id = res.upload_id.as_deref().unwrap();

    println!("upload ID {} ...", upload_id);

    let mut total_size = 0;
    let mut parts = Vec::new();
    loop {
        let mut buf = BytesMut::with_capacity(5 * 1024 * 1024);
        buf.resize(5 * 1024 * 1024, 0);
        let sz = f.read(&mut buf)?;
        if sz == 0 {
            break;
        }

        let part_number = (parts.len() + 1) as i64;
        println!("part {} size {}", part_number, sz);
        total_size += sz;

        /*
         * This was most tedious to work out:
         */
        let froz = buf.split_to(sz).freeze();
        let se = futures::stream::once(async { Ok(froz) });
        let body = Some(rusoto_s3::StreamingBody::new(se));

        let res = s.s3.upload_part(UploadPartRequest {
            body,
            content_length: Some(sz as i64),
            upload_id: upload_id.to_string(),
            key: object.to_string(),
            bucket: bucket.to_string(),
            part_number,
            ..Default::default()
        }).await?;

        let etag = res.e_tag.expect("etag");
        println!("    part {} etag {}", part_number, etag);
        parts.push(CompletedPart {
            part_number: Some(part_number),
            e_tag: Some(etag)
        });
    }

    println!("uploaded {} chunks, total size {}", parts.len(), total_size);

    s.s3.complete_multipart_upload(CompleteMultipartUploadRequest {
        bucket: bucket.to_string(),
        key: object.to_string(),
        upload_id: upload_id.to_string(),
        multipart_upload: Some(CompletedMultipartUpload {
            parts: Some(parts),
        }),
        ..Default::default()
    }).await?;

    println!("upload ok!");
    Ok(())
}

#[derive(Debug)]
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
    println!("  IMAGE SIZE: {:?}", sz);

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
        &sign_delete(s.credprov, &s.region_s3, bkt, kmanifest).await?)?;

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
    w.simple_tag("head-url", &sign_head(s.credprov, &s.region_s3, bkt, kimage)
        .await?)?;
    w.simple_tag("get-url", &sign_get(s.credprov, &s.region_s3, bkt, kimage)
        .await?)?;
    w.simple_tag("delete-url", &sign_delete(s.credprov, &s.region_s3, bkt,
        kimage).await?)?;
    w.write(XmlEvent::end_element())?; /* part */

    w.write(XmlEvent::end_element())?; /* parts */
    w.write(XmlEvent::end_element())?; /* import */
    w.write(XmlEvent::end_element())?; /* manifest */

    out.write_all(b"\n")?;

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

    let availability_zone = s.region_ec2.name().to_string() + "a";
    let import_manifest_url = sign_get(s.credprov, &s.region_s3, bkt,
        &kmanifest).await?;
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

        let mut v = res.conversion_tasks.ok_or_else(|| anyhow!("no ct"))?;

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

pub fn genkey(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(|c| c as char)
        .collect()
}

struct InstanceOptions {
    ami_id: String,
    type_name: String,
    key_name: String,
    tags: HashMap<String, String>,
    root_size_gb: u32,
    subnet_id: String,
    sg_id: String,
    user_data: Option<String>,
    public_ip: Option<bool>,
}

async fn i_create_instance(s: Stuff<'_>, io: &InstanceOptions)
    -> Result<String>
{
    let tag_specifications = if !io.tags.is_empty() {
        let mut tags = Vec::new();
        for (k, v) in io.tags.iter() {
            tags.push(Tag {
                key: ss(k.as_str()),
                value: ss(v.as_str()),
            });
        }
        Some(vec![TagSpecification {
            resource_type: ss("instance"),
            tags: Some(tags),
        }])
    } else {
        None
    };

    let rir = RunInstancesRequest {
        image_id: ss(&io.ami_id),
        instance_type: ss(&io.type_name),
        key_name: ss(&io.key_name),
        min_count: 1,
        max_count: 1,
        tag_specifications,
        block_device_mappings: Some(vec![
            BlockDeviceMapping {
                device_name: ss("/dev/sda1"),
                ebs: Some(EbsBlockDevice {
                    volume_size: Some(io.root_size_gb as i64),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        network_interfaces: Some(vec![
            InstanceNetworkInterfaceSpecification {
                device_index: Some(0),
                subnet_id: ss(&io.subnet_id),
                groups: Some(vec![
                    io.sg_id.to_string(),
                ]),
                associate_public_ip_address: io.public_ip,
                ..Default::default()
            },
        ]),
        user_data: io.user_data.as_deref().map(base64::encode),
        ..Default::default()
    };

    let res = s.ec2.run_instances(rir).await?;
    let mut ids = Vec::new();
    if let Some(insts) = &res.instances {
        for i in insts.iter() {
            ids.push(i.instance_id.as_deref().unwrap().to_string());
        }
    }

    if ids.len() != 1 {
        bail!("wanted one instance, got {:?}", ids);
    } else {
        Ok(ids[0].to_string())
    }
}

async fn create_instance(s: Stuff<'_>) -> Result<()> {
    /*
     * If an instance defaults file was provided, load it now:
     */
    let defs: HashMap<String, String> = if let Some(p) = s.args.opt_str("f") {
        let mut f = File::open(&p)?;
        let mut buf = Vec::<u8>::new();
        f.read_to_end(&mut buf)?;
        toml::from_slice(buf.as_slice())?
    } else {
        HashMap::new()
    };

    let fetchopt = |n: &str| -> Option<String> {
        if let Some(v) = s.args.opt_str(n) {
            Some(v)
        } else if let Some(v) = defs.get(n) {
            Some(v.to_string())
        } else {
            None
        }
    };
    let fetch = |n: &str| -> Result<String> {
        fetchopt(n).ok_or_else(|| anyhow!("must specify option \"{}\"", n))
    };
    let fetch_u32 = |n: &str| -> Result<u32> {
        Ok(fetchopt(n)
            .ok_or_else(|| anyhow!("must specify option \"{}\"", n))?
            .parse::<u32>()
            .map_err(|e| anyhow!("option \"{}\" must be a u32: {:?}", n, e))?)
    };

    let mut tags = HashMap::new();
    tags.insert("Name".to_string(), fetch("name")?);

    let public_ip = if s.args.opt_present("p") {
        Some(true)
    } else {
        None
    };

    let io = InstanceOptions {
        ami_id: fetch("image")?,
        type_name: fetch("type")?,
        key_name: fetch("key")?,
        tags,
        root_size_gb: fetch_u32("disksize")?,
        subnet_id: fetch("subnet")?,
        sg_id: fetch("sg")?,
        user_data: fetchopt("userdata"),
        public_ip,
    };

    let id = i_create_instance(s, &io).await?;
    println!("CREATED INSTANCE {}", id);

    Ok(())
}

async fn ami_from_file(s: Stuff<'_>) -> Result<()> {
    let name = s.args.opt_str("n").unwrap();
    let pfx = if let Some(pfx) = s.args.opt_str("p") {
        pfx
    } else {
        genkey(64)
    };
    let bucket = s.args.opt_str("b").unwrap();
    let file = s.args.opt_str("f").unwrap();
    let support_ena = s.args.opt_present("E");

    let kimage = pfx.clone() + "/disk.raw";
    let kmanifest = pfx.clone() + "/manifest.xml";

    println!("UPLOADING DISK TO S3 AS: {}", kimage);
    i_put_object(s, &bucket, &kimage, &file).await?;
    println!("COMPLETED UPLOAD");

    println!("IMPORTING VOLUME:");
    let volid = i_import_volume(s, &bucket, &kimage, &kmanifest).await?;
    println!("COMPLETED VOLUME ID: {}", volid);

    println!("CREATING SNAPSHOT:");
    let snapid = i_create_snapshot(s, &volid).await?;
    println!("COMPLETED SNAPSHOT ID: {}", snapid);

    println!("REGISTERING IMAGE:");
    let ami = i_register_image(s, &name, &snapid, support_ena).await?;
    println!("COMPLETED IMAGE ID: {}", ami);

    /*
     * XXX Should remove volume after registration?
     */

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
    let mut last_state = String::new();

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
                if last_state != n {
                    println!("    state is {}", n);
                    last_state = n.to_string();
                }
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

async fn stop_instance(s: &Stuff<'_>, id: &str, force: bool) -> Result<()> {
    let lookup = InstanceLookup::ById(id.to_string());

    let pfx = if force {
        "force "
    } else {
        ""
    };

    println!("{}stopping instance {}...", pfx, id);

    let mut stopped = false;
    let mut last_state = String::new();

    loop {
        let inst = get_instance(s, lookup.clone()).await?;

        let shouldstop = match inst.state.as_str() {
            n @ "stopped" => {
                println!("    state is {}; done!", n);
                return Ok(());
            }
            n => {
                if last_state != n {
                    println!("    state is {}", n);
                    last_state = n.to_string();
                }
                n == "running"
            }
        };

        if shouldstop && !stopped {
            println!("    {}stopping...", pfx);
            let res = s.ec2.stop_instances(ec2::StopInstancesRequest {
                instance_ids: vec![id.to_string()],
                force: Some(force),
                ..Default::default()
            }).await?;
            println!("    {:#?}", res);
            stopped = true;
        }

        sleep(1000);
    }
}

async fn protect_instance(s: &Stuff<'_>, id: &str, prot: bool) -> Result<()> {
    println!("setting protect to {} on instance {}...", prot, id);

    let val = ec2::AttributeBooleanValue {
        value: Some(prot),
    };

    s.ec2.modify_instance_attribute(
        ec2::ModifyInstanceAttributeRequest {
            instance_id: id.to_string(),
            disable_api_termination: Some(val),
            ..Default::default()
        }).await?;

    Ok(())
}

async fn destroy_instance(s: &Stuff<'_>, id: &str) -> Result<()> {
    let lookup = InstanceLookup::ById(id.to_string());

    println!("destroying instance {}...", id);

    let mut terminated = false;
    let mut last_state = String::new();

    loop {
        let inst = get_instance(s, lookup.clone()).await?;

        let shouldterminate = match inst.state.as_str() {
            n @ "terminated" => {
                println!("    state is {}; done!", n);
                return Ok(());
            }
            n => {
                if last_state != n {
                    println!("    state is {}", n);
                    last_state = n.to_string();
                }
                n != "shutting-down"
            }
        };

        if shouldterminate && !terminated {
            println!("    terminating...");
            let res = s.ec2.terminate_instances(ec2::TerminateInstancesRequest {
                instance_ids: vec![id.to_string()],
                ..Default::default()
            }).await?;
            println!("    {:#?}", res);
            terminated = true;
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
                id.as_str() == vol.volume_id.as_deref().unwrap()
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

async fn get_instance_fuzzy(s: &Stuff<'_>, lookuparg: &str)
    -> Result<Instance>
{
    let lookup = if lookuparg.starts_with("i-") {
        InstanceLookup::ById(lookuparg.to_string())
    } else {
        InstanceLookup::ByName(lookuparg.to_string())
    };

    Ok(get_instance(s, lookup).await?)
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
                    id.as_str() == inst.instance_id.as_deref().unwrap()
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

async fn ip(s: Stuff<'_>) -> Result<()> {
    if s.args.free.len() != 1 {
        bail!("specify just one instance");
    }
    let n = s.args.free[0].as_str();

    let i = get_instance_fuzzy(&s, n).await?;
    if let Some(ip) = i.ip {
        println!("{}", ip);
        Ok(())
    } else {
        bail!("no IP address for instance {} ({})", n, i.id);
    }
}

async fn info(s: Stuff<'_>) -> Result<()> {
    let mut t = TableBuilder::new();
    t.add_column("id", 19);
    t.add_column("name", 28);
    t.add_column("launch", 24);
    t.add_column("ip", 15);
    t.add_column("state", 16);
    t.add_column("type", 12);
    for tag in s.args.opt_strs("T") {
        t.add_column(&tag, 20);
    }
    t.output_from_list(Some("id,name,ip,state"));
    t.output_from_list(s.args.opt_str("o").as_deref());
    t.sort_from_list_desc(Some("launch"));
    t.sort_from_list_asc(s.args.opt_str("s").as_deref());
    t.sort_from_list_desc(s.args.opt_str("S").as_deref());
    t.disable_header(s.args.opt_present("H"));
    let mut t = t.build();

    if !s.args.free.is_empty() {
        for n in s.args.free.iter() {
            let i = get_instance_fuzzy(&s, n).await?;

            let mut r = Row::new();
            r.add_str("id", &i.id);
            r.add_stror("name", &i.name, "-");
            r.add_str("launch", &i.launch);
            r.add_stror("ip", &i.ip, "-");
            r.add_str("state", &i.state);
            for tag in s.args.opt_strs("T") {
                r.add_str(&tag, "-"); /* XXX */
            }
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

                        let pubip = i.public_ip_address.as_deref();
                        let privip = i.private_ip_address.as_deref();

                        r.add_stror("type", &i.instance_type, "-");
                        r.add_str("id", i.instance_id.as_deref().unwrap());
                        r.add_stror("name", &i.tags.tag("Name"), "-");
                        r.add_str("launch", i.launch_time.as_deref().unwrap());
                        r.add_str("ip", pubip.unwrap_or(privip.unwrap_or("-")));
                        r.add_str("state", i.state.as_ref().unwrap()
                            .name.as_deref().unwrap());

                        for tag in s.args.opt_strs("T") {
                            r.add_stror(&tag, &i.tags.tag(&tag), "-");
                        }

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

    let i = get_instance_fuzzy(&s, s.args.free.get(0).unwrap()).await?;

    println!("starting instance: {:?}", i);

    start_instance(&s, &i.id).await?;

    println!("all done!");

    Ok(())
}

async fn stop(s: Stuff<'_>) -> Result<()> {
    let force = s.args.opt_present("f");

    if s.args.free.len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(&s, s.args.free.get(0).unwrap()).await?;

    println!("stopping instance: {:?}", i);

    stop_instance(&s, &i.id, force).await?;

    println!("all done!");

    Ok(())
}

async fn protect(s: Stuff<'_>, protect: bool) -> Result<()> {
    if s.args.free.len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(&s, s.args.free.get(0).unwrap()).await?;

    if protect {
        println!("protecting instance: {:?}", i);
    } else {
        println!("unprotecting instance: {:?}", i);
    }

    protect_instance(&s, &i.id, protect).await?;

    println!("all done!");

    Ok(())
}

async fn destroy(s: Stuff<'_>) -> Result<()> {
    if s.args.free.len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(&s, s.args.free.get(0).unwrap()).await?;

    println!("destroying instance: {:?}", i);

    destroy_instance(&s, &i.id).await?;

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
            stop_instance(&s, &i_melbourne.id, false).await?;

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
    region_s3: &'a Region,
    ec2: &'a dyn Ec2,
    region_ec2: &'a Region,
    credprov: &'a dyn ProvideAwsCredentials,
    args: &'a getopts::Matches,
}

type Caller<'a> = fn(Stuff<'a>)
    -> Pin<Box<(dyn Future<Output = Result<()>> + 'a)>>;

#[tokio::main]
async fn main() -> Result<()> {
    let mut opts = getopts::Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.optflag("e", "", "use environment variables for credentials");
    opts.optopt("r", "region-ec2", "region for EC2", "REGION");
    opts.optopt("R", "region-s3", "region for S3", "REGION");
    opts.optflag("", "help", "print usage");

    fn tabular(opts: &mut getopts::Options) {
        opts.optopt("s", "", "sort by columns (ascending)", "COLUMN,...");
        opts.optopt("S", "", "sort by columns (descending)", "COLUMN,...");
        opts.optopt("o", "", "select columns to display", "COLUMN,...");
        opts.optflag("H", "", "omit header");
    }

    let f: Caller = match std::env::args().nth(1).as_deref() {
        Some("start") => {
            |s| Box::pin(start(s))
        }
        Some("stop") => {
            opts.optflag("f", "", "force stop");

            |s| Box::pin(stop(s))
        }
        Some("protect") => {
            |s| Box::pin(protect(s, true))
        }
        Some("unprotect") => {
            |s| Box::pin(protect(s, false))
        }
        Some("destroy") => {
            |s| Box::pin(destroy(s))
        }
        Some("ip") => {
            |s| Box::pin(ip(s))
        }
        Some("info") => {
            tabular(&mut opts);
            opts.optmulti("T", "", "specify a tag as an extra column", "TAG");

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
        Some("create") => {
            opts.optopt("n", "name", "instance name", "NAME");
            opts.optopt("i", "image", "image (AMI)", "AMI_ID");
            opts.optopt("t", "type", "instance type", "TYPE");
            opts.optopt("k", "key", "SSH key name", "KEY_NAME");
            opts.optopt("s", "sg", "security group ID", "SG_ID");
            opts.optopt("S", "subnet", "subnet ID", "SUBNET_ID");
            opts.optopt("u", "userdata", "userdata (in plain text)", "DATA");
            opts.optopt("d", "disksize", "root disk size (GB)", "GIGABYTES");
            opts.optopt("f", "file", "defaults TOML file to use", "PATH");
            opts.optflag("p", "public-ip", "request a public IP");

            |s| Box::pin(create_instance(s))
        }
        Some("everything") | Some("ami-from-file") => {
            opts.reqopt("b", "bucket", "S3 bucket", "BUCKET");
            opts.optopt("p", "prefix", "S3 prefix", "PREFIX");
            opts.reqopt("n", "name", "target image name", "NAME");
            opts.optflag("E", "ena", "enable ENA support");
            opts.reqopt("f", "file", "local file to upload", "FILENAME");

            |s| Box::pin(ami_from_file(s))
        }
        Some("put-object") => {
            opts.reqopt("b", "bucket", "S3 bucket", "BUCKET");
            opts.reqopt("o", "object", "S3 object name", "OBJECT");
            opts.reqopt("f", "file", "local file to upload", "FILENAME");

            |s| Box::pin(put_object(s))
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

    let usage = || {
        let prog = std::env::args().nth(0).as_deref().unwrap().to_string();
        let cmd = std::env::args().nth(1).as_deref().unwrap().to_string();
        opts.usage(&format!("usage: {} {} OPTIONS", prog, cmd))
    };

    let args = match opts.parse(std::env::args().skip(2)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", usage());
            eprintln!("ERROR: {}", e);
            std::process::exit(1);
        }
    };

    if args.opt_present("help") {
        println!("{}", usage());
        std::process::exit(0);
    }

    let credprov: Box<dyn ProvideAwsCredentials> = if args.opt_present("e") {
        Box::new(EnvironmentProvider::default())
    } else {
        Box::new(DefaultCredentialsProvider::new()?)
    };

    let region_s3 = if let Some(reg) = args.opt_str("region-s3").as_deref() {
        Region::from_str(reg).context("invalid S3 region")?
    } else {
        Region::default()
    };
    let region_ec2 = if let Some(reg) = args.opt_str("region-ec2").as_deref() {
        Region::from_str(reg).context("invalid EC2 region")?
    } else {
        Region::default()
    };

    let (s3, ec2) = if args.opt_present("e") {
        let s3 = S3Client::new_with(HttpClient::new()?,
            EnvironmentProvider::default(),
            region_s3.clone());
        let ec2 = Ec2Client::new_with(HttpClient::new()?,
            EnvironmentProvider::default(),
            region_ec2.clone());
        (s3, ec2)
    } else {
        let s3 = S3Client::new_with(HttpClient::new()?,
            DefaultCredentialsProvider::new()?,
            region_s3.clone());
        let ec2 = Ec2Client::new_with(HttpClient::new()?,
            DefaultCredentialsProvider::new()?,
            region_ec2.clone());
        (s3, ec2)
    };

    f(Stuff {
        s3: &s3,
        region_s3: &region_s3,
        ec2: &ec2,
        region_ec2: &region_ec2,
        credprov: credprov.as_ref(),
        args: &args,
    }).await?;

    Ok(())
}

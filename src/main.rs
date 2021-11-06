/*
 * Copyright 2021 Oxide Computer Company
 */

#![allow(clippy::many_single_char_names)]

use anyhow::{anyhow, bail, Context, Result};
use bytes::BytesMut;
use ec2::{
    BlockDeviceMapping, CreateSnapshotRequest, DeleteSnapshotRequest,
    DeleteVolumeRequest, DeregisterImageRequest,
    DescribeConversionTasksRequest, DescribeImagesRequest,
    DescribeSnapshotsRequest, DiskImageDetail, EbsBlockDevice, Ec2, Ec2Client,
    ImportVolumeRequest, InstanceNetworkInterfaceSpecification,
    RegisterImageRequest, RunInstancesRequest, Tag, TagSpecification,
    VolumeDetail,
};
use ec2ic::{Ec2InstanceConnect, Ec2InstanceConnectClient};
use hiercmd::prelude::*;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rsa::pkcs8::{FromPrivateKey, ToPrivateKey};
use rsa::PublicKeyParts;
use rusoto_core::param::Params;
use rusoto_core::signature::SignedRequest;
use rusoto_core::RusotoError;
use rusoto_core::{HttpClient, Region};
use rusoto_credential::{
    DefaultCredentialsProvider, EnvironmentProvider, ProvideAwsCredentials,
};
use rusoto_ec2 as ec2;
use rusoto_ec2_instance_connect as ec2ic;
use rusoto_s3 as s3;
use rusoto_s3::util::{PreSignedRequest, PreSignedRequestOption};
use rusoto_sts as sts;
use s3::{
    CompleteMultipartUploadRequest, CompletedMultipartUpload, CompletedPart,
    CreateMultipartUploadRequest, DeleteObjectRequest, GetObjectRequest,
    HeadObjectRequest, PutObjectRequest, S3Client, UploadPartRequest, S3,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::str::FromStr;
use std::time::Duration;
use sts::AssumeRoleRequest;
use sts::{Sts, StsClient};
use xml::writer::{EmitterConfig, EventWriter, XmlEvent};

trait RowExt {
    fn add_stror(&mut self, n: &str, v: &Option<String>, def: &str);
}

impl RowExt for Row {
    fn add_stror(&mut self, n: &str, v: &Option<String>, def: &str) {
        self.add_str(n, v.as_deref().unwrap_or(def));
    }
}

trait AsFlag {
    fn as_flag(&self, f: &str) -> String;
}

impl AsFlag for Option<bool> {
    fn as_flag(&self, f: &str) -> String {
        if let Some(val) = self {
            if *val {
                f
            } else {
                "-"
            }
        } else {
            "-"
        }
        .to_string()
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

async fn sign_delete(
    c: &dyn ProvideAwsCredentials,
    r: &Region,
    b: &str,
    k: &str,
) -> Result<String> {
    let creds = c.credentials().await?;
    Ok(DeleteObjectRequest {
        bucket: b.to_string(),
        key: k.to_string(),
        ..Default::default()
    }
    .get_presigned_url(
        r,
        &creds,
        &PreSignedRequestOption {
            expires_in: Duration::from_secs(3600),
        },
    ))
}

async fn sign_head(
    c: &dyn ProvideAwsCredentials,
    r: &Region,
    b: &str,
    k: &str,
) -> Result<String> {
    let creds = c.credentials().await?;
    let uri = format!("/{}/{}", b, k);
    let mut req = SignedRequest::new("HEAD", "s3", r, &uri);
    let params = Params::new();

    let expires_in = Duration::from_secs(3600);

    req.set_params(params);
    Ok(req.generate_presigned_url(&creds, &expires_in, false))
}

async fn sign_get(
    c: &dyn ProvideAwsCredentials,
    r: &Region,
    b: &str,
    k: &str,
) -> Result<String> {
    let creds = c.credentials().await?;
    Ok(GetObjectRequest {
        bucket: b.to_string(),
        key: k.to_string(),
        ..Default::default()
    }
    .get_presigned_url(
        r,
        &creds,
        &PreSignedRequestOption {
            expires_in: Duration::from_secs(300),
        },
    ))
}

// async fn put_object(mut l: Level<Stuff>) -> Result<()> {
//     let bucket = s.args.opt_str("b").unwrap();
//     let object = s.args.opt_str("o").unwrap();
//     let file = s.args.opt_str("f").unwrap();
//
//     i_put_object(s, &bucket, &object, &file).await?;
//     Ok(())
// }

async fn i_put_object(
    s: &Stuff,
    bucket: &str,
    object: &str,
    file: &str,
) -> Result<()> {
    let mut f = File::open(&file)?;

    let res = s
        .s3()
        .create_multipart_upload(CreateMultipartUploadRequest {
            bucket: bucket.to_string(),
            key: object.to_string(),
            ..Default::default()
        })
        .await?;
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

        let res = s
            .s3()
            .upload_part(UploadPartRequest {
                body,
                content_length: Some(sz as i64),
                upload_id: upload_id.to_string(),
                key: object.to_string(),
                bucket: bucket.to_string(),
                part_number,
                ..Default::default()
            })
            .await?;

        let etag = res.e_tag.expect("etag");
        println!("    part {} etag {}", part_number, etag);
        parts.push(CompletedPart {
            part_number: Some(part_number),
            e_tag: Some(etag),
        });
    }

    println!("uploaded {} chunks, total size {}", parts.len(), total_size);

    s.s3()
        .complete_multipart_upload(CompleteMultipartUploadRequest {
            bucket: bucket.to_string(),
            key: object.to_string(),
            upload_id: upload_id.to_string(),
            multipart_upload: Some(CompletedMultipartUpload {
                parts: Some(parts),
            }),
            ..Default::default()
        })
        .await?;

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
    let ikh = s3
        .head_object(HeadObjectRequest {
            bucket: b.to_string(),
            key: k.to_string(),
            ..Default::default()
        })
        .await?;

    /*
     * We need the size in bytes, as well as the size in GiB rounded up to the
     * next GiB (so that the created volume is large enough to contain the
     * image.
     */
    let bytes = ikh.content_length.unwrap();
    let gb = (bytes + (1 << 30) - 1) / (1 << 30);

    Ok(ImageSizes { bytes, gb })
}

// async fn import_volume(mut l: Level<Stuff>) -> Result<()> {
//     let pfx = s.args.opt_str("p").unwrap();
//     let bucket = s.args.opt_str("b").unwrap();
//     let kimage = pfx.clone() + "/disk.raw";
//     let kmanifest = pfx.clone() + "/manifest.xml";
//
//     let volid = i_import_volume(s, &bucket, &kimage, &kmanifest).await?;
//     println!("COMPLETED VOLUME ID: {}", volid);
//
//     Ok(())
// }

async fn i_import_volume(
    s: &Stuff,
    bkt: &str,
    kimage: &str,
    kmanifest: &str,
) -> Result<String> {
    let sz = image_size(s.s3(), bkt, kimage).await?;
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

    w.simple_tag(
        "self-destruct-url",
        &sign_delete(s.credprov(), s.region_s3(), bkt, kmanifest).await?,
    )?;

    w.write(XmlEvent::start_element("import"))?;

    w.simple_tag("size", &sz.bytes())?;
    w.simple_tag("volume-size", &sz.gb())?;
    w.write(XmlEvent::start_element("parts").attr("count", "1"))?;

    w.write(XmlEvent::start_element("part").attr("index", "0"))?;
    w.write(
        XmlEvent::start_element("byte-range")
            .attr("start", "0")
            .attr("end", &sz.end()),
    )?;
    w.write(XmlEvent::end_element())?; /* byte-range */
    w.simple_tag("key", kimage)?;
    w.simple_tag(
        "head-url",
        &sign_head(s.credprov(), s.region_s3(), bkt, kimage).await?,
    )?;
    w.simple_tag(
        "get-url",
        &sign_get(s.credprov(), s.region_s3(), bkt, kimage).await?,
    )?;
    w.simple_tag(
        "delete-url",
        &sign_delete(s.credprov(), s.region_s3(), bkt, kimage).await?,
    )?;
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
    s.s3().put_object(req).await?;

    println!("ok!");

    println!("importing volume...");

    let availability_zone = s.region_ec2().name().to_string() + "a";
    let import_manifest_url =
        sign_get(s.credprov(), s.region_s3(), bkt, kmanifest).await?;
    let res = s
        .ec2()
        .import_volume(ImportVolumeRequest {
            availability_zone,
            dry_run: Some(false),
            image: DiskImageDetail {
                format: "RAW".to_string(),
                import_manifest_url,
                bytes: sz.bytes,
            },
            volume: VolumeDetail { size: sz.gb },
            description: None,
        })
        .await?;

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

        let res = s.ec2().describe_conversion_tasks(dct).await?;

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

// async fn create_snapshot(mut l: Level<Stuff>) -> Result<()> {
//     let volid = s.args.opt_str("v").unwrap();
//
//     let snapid = i_create_snapshot(s, &volid).await?;
//     println!("COMPLETED SNAPSHOT ID: {}", snapid);
//
//     Ok(())
// }

async fn i_create_snapshot(s: &Stuff, volid: &str) -> Result<String> {
    let res = s
        .ec2()
        .create_snapshot(CreateSnapshotRequest {
            volume_id: volid.to_string(),
            ..Default::default()
        })
        .await?;

    println!("res: {:#?}", res);

    let snapid = res.snapshot_id.unwrap();
    println!("SNAPSHOT ID: {}", snapid);

    loop {
        let res = s
            .ec2()
            .describe_snapshots(DescribeSnapshotsRequest {
                snapshot_ids: Some(vec![snapid.clone()]),
                ..Default::default()
            })
            .await?;

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

async fn i_create_instance(s: &Stuff, io: &InstanceOptions) -> Result<String> {
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
        block_device_mappings: Some(vec![BlockDeviceMapping {
            device_name: ss("/dev/sda1"),
            ebs: Some(EbsBlockDevice {
                volume_size: Some(io.root_size_gb as i64),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        network_interfaces: Some(vec![InstanceNetworkInterfaceSpecification {
            device_index: Some(0),
            subnet_id: ss(&io.subnet_id),
            groups: Some(vec![io.sg_id.to_string()]),
            associate_public_ip_address: io.public_ip,
            ..Default::default()
        }]),
        user_data: io.user_data.as_deref().map(base64::encode),
        ..Default::default()
    };

    let res = s.ec2().run_instances(rir).await?;
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

async fn create_instance(mut l: Level<Stuff>) -> Result<()> {
    l.optopt("n", "name", "instance name", "NAME");
    l.optopt("i", "image", "image (AMI)", "AMI_ID");
    l.optopt("t", "type", "instance type", "TYPE");
    l.optopt("k", "key", "SSH key name", "KEY_NAME");
    l.optopt("s", "sg", "security group ID", "SG_ID");
    l.optopt("S", "subnet", "subnet ID", "SUBNET_ID");
    l.optopt("u", "userdata", "userdata (in plain text)", "DATA");
    l.optopt("d", "disksize", "root disk size (GB)", "GIGABYTES");
    l.optopt("f", "file", "defaults TOML file to use", "PATH");
    l.optflag("p", "public-ip", "request a public IP");

    let a = args!(l);

    /*
     * If an instance defaults file was provided, load it now:
     */
    let defs: HashMap<String, String> = if let Some(p) = a.opts().opt_str("f") {
        let mut f = File::open(&p)?;
        let mut buf = Vec::<u8>::new();
        f.read_to_end(&mut buf)?;
        toml::from_slice(buf.as_slice())?
    } else {
        HashMap::new()
    };

    let fetchopt = |n: &str| -> Option<String> {
        if let Some(v) = a.opts().opt_str(n) {
            Some(v)
        } else {
            defs.get(n).map(|v| v.to_string())
        }
    };
    let fetch = |n: &str| -> Result<String> {
        if let Some(v) = fetchopt(n) {
            Ok(v)
        } else {
            bad_args!(l, "must specify option \"{}\"", n);
        }
    };
    let fetch_u32 = |n: &str| -> Result<u32> {
        match fetch(n)?.parse::<u32>() {
            Ok(v) => Ok(v),
            Err(e) => {
                bad_args!(l, "option \"{}\" must be a u32: {:?}", n, e);
            }
        }
    };

    let mut tags = HashMap::new();
    tags.insert("Name".to_string(), fetch("name")?);

    let public_ip = if a.opts().opt_present("p") {
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

    let id = i_create_instance(l.context(), &io).await?;
    println!("CREATED INSTANCE {}", id);

    Ok(())
}

async fn ami_from_file(mut l: Level<Stuff>) -> Result<()> {
    l.reqopt("b", "bucket", "S3 bucket", "BUCKET");
    l.optopt("p", "prefix", "S3 prefix", "PREFIX");
    l.reqopt("n", "name", "target image name", "NAME");
    l.optflag("E", "ena", "enable ENA support");
    l.reqopt("f", "file", "local file to upload", "FILENAME");

    let a = no_args!(l);

    let name = a.opts().opt_str("n").unwrap();
    let pfx = if let Some(pfx) = a.opts().opt_str("p") {
        pfx
    } else {
        genkey(64)
    };
    let bucket = a.opts().opt_str("b").unwrap();
    let file = a.opts().opt_str("f").unwrap();
    let support_ena = a.opts().opt_present("E");

    let kimage = pfx.clone() + "/disk.raw";
    let kmanifest = pfx.clone() + "/manifest.xml";

    println!("UPLOADING DISK TO S3 AS: {}", kimage);
    i_put_object(l.context(), &bucket, &kimage, &file).await?;
    println!("COMPLETED UPLOAD");

    println!("IMPORTING VOLUME:");
    let volid =
        i_import_volume(l.context(), &bucket, &kimage, &kmanifest).await?;
    println!("COMPLETED VOLUME ID: {}", volid);

    println!("CREATING SNAPSHOT:");
    let snapid = i_create_snapshot(l.context(), &volid).await?;
    println!("COMPLETED SNAPSHOT ID: {}", snapid);

    println!("REMOVING VOLUME:");
    if let Err(e) = i_volume_rm(l.context(), &volid, false).await {
        /*
         * Seeing as we have done almost all of the actual work at this point,
         * don't fail the command if we cannot delete the volume now.
         */
        println!("WARNING: COULD NOT REMOVE VOLUME: {:?}", e);
    } else {
        println!("REMOVED VOLUME ID: {}", volid);
    }

    println!("REGISTERING IMAGE:");
    let ami =
        i_register_image(l.context(), &name, &snapid, support_ena).await?;
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

#[allow(dead_code)]
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
    tags: Vec<Tag>,
}

#[derive(Debug, Clone)]
enum InstanceLookup {
    ById(String),
    ByName(String),
}

#[allow(dead_code)]
async fn detach_volume(s: &Stuff, id: &str) -> Result<()> {
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
                let res = s
                    .ec2()
                    .detach_volume(ec2::DetachVolumeRequest {
                        volume_id: vol.id.clone(),
                        ..Default::default()
                    })
                    .await?;

                println!("    {:#?}", res);
                detached = true;
            }
        }

        sleep(1000);
    }
}

async fn start_instance(s: &Stuff, id: &str) -> Result<()> {
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
            let res = s
                .ec2()
                .start_instances(ec2::StartInstancesRequest {
                    instance_ids: vec![id.to_string()],
                    ..Default::default()
                })
                .await?;
            println!("    {:#?}", res);
            started = true;
        }

        sleep(1000);
    }
}

async fn stop_instance(s: &Stuff, id: &str, force: bool) -> Result<()> {
    let lookup = InstanceLookup::ById(id.to_string());

    let pfx = if force { "force " } else { "" };

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

        if (force || shouldstop) && !stopped {
            println!("    {}stopping...", pfx);
            let res = s
                .ec2()
                .stop_instances(ec2::StopInstancesRequest {
                    instance_ids: vec![id.to_string()],
                    force: Some(force),
                    ..Default::default()
                })
                .await?;
            println!("    {:#?}", res);
            stopped = true;
        }

        sleep(1000);
    }
}

async fn protect_instance(s: &Stuff, id: &str, prot: bool) -> Result<()> {
    println!("setting protect to {} on instance {}...", prot, id);

    let val = ec2::AttributeBooleanValue { value: Some(prot) };

    s.ec2()
        .modify_instance_attribute(ec2::ModifyInstanceAttributeRequest {
            instance_id: id.to_string(),
            disable_api_termination: Some(val),
            ..Default::default()
        })
        .await?;

    Ok(())
}

async fn destroy_instance(s: &Stuff, id: &str) -> Result<()> {
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
            let res = s
                .ec2()
                .terminate_instances(ec2::TerminateInstancesRequest {
                    instance_ids: vec![id.to_string()],
                    ..Default::default()
                })
                .await?;
            println!("    {:#?}", res);
            terminated = true;
        }

        sleep(1000);
    }
}

#[allow(dead_code)]
async fn get_volume(s: &Stuff, lookup: VolumeLookup) -> Result<Volume> {
    let filters = match &lookup {
        VolumeLookup::ById(id) => Some(vec![ec2::Filter {
            name: Some("volume-id".into()),
            values: Some(vec![id.into()]),
        }]),
        VolumeLookup::ByName(name) => Some(vec![ec2::Filter {
            name: Some("tag:Name".into()),
            values: Some(vec![name.into()]),
        }]),
    };

    let res = s
        .ec2()
        .describe_volumes(ec2::DescribeVolumesRequest {
            filters,
            ..Default::default()
        })
        .await?;

    let mut out: Vec<Volume> = Vec::new();

    for vol in res.volumes.as_ref().unwrap_or(&vec![]).iter() {
        /*
         * Find the name tag value:
         */
        let tags = vol.tags.as_ref().unwrap();
        let nametag = tags
            .iter()
            .find(|t| t.key.as_deref() == Some("Name"))
            .and_then(|t| t.value.as_deref());

        let mat = match &lookup {
            VolumeLookup::ById(id) => {
                id.as_str() == vol.volume_id.as_deref().unwrap()
            }
            VolumeLookup::ByName(name) => Some(name.as_str()) == nametag,
        };

        if mat {
            /*
             * Check into the attach state.
             */
            let attach = if let Some(att) = vol.attachments.as_ref() {
                if att.len() > 1 {
                    bail!(
                        "matching volume has {} attachments: {:#?}",
                        att.len(),
                        vol
                    );
                } else if att.len() == 1 {
                    let a = att.get(0).unwrap();
                    Some(Attach {
                        state: a.state.as_deref().unwrap().to_string(),
                        instance_id: a
                            .instance_id
                            .as_deref()
                            .unwrap()
                            .to_string(),
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

async fn get_instance_fuzzy(s: &Stuff, lookuparg: &str) -> Result<Instance> {
    let lookup = if lookuparg.starts_with("i-") {
        InstanceLookup::ById(lookuparg.to_string())
    } else {
        InstanceLookup::ByName(lookuparg.to_string())
    };

    Ok(get_instance_x(s, lookup, true).await?)
}

async fn get_instance(s: &Stuff, lookup: InstanceLookup) -> Result<Instance> {
    Ok(get_instance_x(s, lookup, false).await?)
}

async fn get_instance_x(
    s: &Stuff,
    lookup: InstanceLookup,
    ignoreterm: bool,
) -> Result<Instance> {
    let filters = match &lookup {
        InstanceLookup::ById(id) => Some(vec![ec2::Filter {
            name: Some("instance-id".into()),
            values: Some(vec![id.into()]),
        }]),
        InstanceLookup::ByName(name) => Some(vec![ec2::Filter {
            name: Some("tag:Name".into()),
            values: Some(vec![name.into()]),
        }]),
    };

    let res = s
        .ec2()
        .describe_instances(ec2::DescribeInstancesRequest {
            filters,
            ..Default::default()
        })
        .await?;

    let mut out: Vec<Instance> = Vec::new();

    for res in res.reservations.as_ref().unwrap_or(&vec![]).iter() {
        for inst in res.instances.as_ref().unwrap_or(&vec![]).iter() {
            if ignoreterm {
                let st = inst.state.as_ref().unwrap().name.as_deref().unwrap();
                if st == "terminated" {
                    continue;
                }
            }

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
                    state: inst
                        .state
                        .as_ref()
                        .unwrap()
                        .name
                        .as_deref()
                        .unwrap()
                        .to_string(),
                    launch: inst.launch_time.as_deref().unwrap().to_string(),
                    tags: inst
                        .tags
                        .as_ref()
                        .map(|o| o.iter().cloned().collect())
                        .unwrap_or_default(),
                });
            }
        }
    }

    if out.is_empty() {
        bail!("could not find instance to match {:?}", lookup);
    }

    if out.len() > 1 {
        bail!(
            "found too many instances that match {:?}: {:#?}",
            lookup,
            out
        );
    }

    Ok(out.pop().unwrap())
}

async fn do_image_rm(mut l: Level<Stuff>) -> Result<()> {
    l.optflag("n", "", "dry run (do not actually delete)");

    let a = args!(l);

    if a.args().is_empty() {
        bad_args!(l, "specify at least one image ID");
    }

    let dry_run = a.opts().opt_present("n");

    for id in a.args() {
        l.context()
            .ec2()
            .deregister_image(DeregisterImageRequest {
                dry_run: Some(dry_run),
                image_id: id.to_string(),
            })
            .await?;
        if dry_run {
            println!("would delete {}", id);
        } else {
            println!("deleted {}", id);
        }
    }

    Ok(())
}

async fn i_volume_rm(s: &Stuff, volid: &str, dry_run: bool) -> Result<()> {
    s.ec2()
        .delete_volume(DeleteVolumeRequest {
            dry_run: Some(dry_run),
            volume_id: volid.to_string(),
        })
        .await?;
    Ok(())
}

async fn do_volume_rm(mut l: Level<Stuff>) -> Result<()> {
    l.optflag("n", "", "dry run (do not actually delete)");

    let a = args!(l);

    if a.args().is_empty() {
        bad_args!(l, "specify at least one volume ID");
    }

    let dry_run = a.opts().opt_present("n");

    for id in a.args() {
        i_volume_rm(l.context(), id.as_str(), dry_run).await?;
        if dry_run {
            println!("would delete {}", id);
        } else {
            println!("deleted {}", id);
        }
    }

    Ok(())
}

async fn do_snapshot_rm(mut l: Level<Stuff>) -> Result<()> {
    l.optflag("n", "", "dry run (do not actually delete)");

    let a = args!(l);

    if a.args().is_empty() {
        bad_args!(l, "specify at least one snapshot ID");
    }

    let dry_run = a.opts().opt_present("n");

    for id in a.args() {
        l.context()
            .ec2()
            .delete_snapshot(DeleteSnapshotRequest {
                dry_run: Some(dry_run),
                snapshot_id: id.to_string(),
            })
            .await?;
        if dry_run {
            println!("would delete {}", id);
        } else {
            println!("deleted {}", id);
        }
    }

    Ok(())
}

async fn snapshots(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", 22, true);
    l.add_column("start", 24, true);
    l.add_column("size", 5, true);
    l.add_column("state", 10, true);
    l.add_column("desc", 30, true);
    l.add_column("volume", 22, false);
    // XXX l.sort_from_list_desc(Some("start"))

    let a = args!(l);
    let mut t = a.table();
    let s = l.context();

    let snapshot_ids = if a.args().is_empty() {
        None
    } else {
        Some(a.args().to_vec())
    };

    let res = s
        .ec2()
        .describe_snapshots(ec2::DescribeSnapshotsRequest {
            owner_ids: Some(vec!["self".to_string()]),
            snapshot_ids,
            ..Default::default()
        })
        .await?;

    let x = Vec::new();
    for s in res.snapshots.as_ref().unwrap_or(&x) {
        let mut r = Row::default();

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

async fn volumes(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("creation", 24, false);
    l.add_column("id", 21, true);
    l.add_column("state", 10, true);
    l.add_column("natt", 4, true); /* Number of attachments */
    l.add_column("info", 30, true);
    l.add_column("size", 5, false);
    l.add_column("snapshot", 22, false);
    l.add_column("name", 24, false);
    l.add_column("az", 14, false);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s
        .ec2()
        .describe_volumes(ec2::DescribeVolumesRequest {
            ..Default::default()
        })
        .await?;

    let x = Vec::new();
    for v in res.volumes.as_ref().unwrap_or(&x) {
        let mut r = Row::default();

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
                let ai = get_instance(s, InstanceLookup::ById(aid.to_string()))
                    .await?;

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

async fn images(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", 21, true);
    l.add_column("name", 24, true);
    l.add_column("creation", 24, true);
    l.add_column("snapshots", 22, false);
    // XXX l.sort_from_list_desc(Some("creation"))

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s
        .ec2()
        .describe_images(ec2::DescribeImagesRequest {
            owners: Some(vec!["self".to_string()]),
            ..Default::default()
        })
        .await?;

    let x = Vec::new();
    for i in res.images.as_ref().unwrap_or(&x) {
        let mut r = Row::default();

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

async fn ip(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);

    if a.args().len() != 1 {
        bail!("specify just one instance");
    }
    let n = a.args()[0].as_str();

    let i = get_instance_fuzzy(l.context(), n).await?;
    if let Some(ip) = i.ip {
        println!("{}", ip);
        Ok(())
    } else {
        bail!("no IP address for instance {} ({})", n, i.id);
    }
}

async fn dump(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bail!("specify a single instance by name or ID");
    }
    let i = get_instance_fuzzy(s, &a.args()[0]).await?;

    println!("INSTANCE {}", i.id);

    let res = s
        .ec2()
        .describe_instance_attribute(ec2::DescribeInstanceAttributeRequest {
            attribute: "disableApiTermination".to_string(),
            instance_id: i.id.to_string(),
            ..Default::default()
        })
        .await?;

    if res
        .disable_api_termination
        .unwrap_or_default()
        .value
        .unwrap_or_default()
    {
        println!("TERMINATION PROTECTION: yes");
    } else {
        println!("TERMINATION PROTECTION: no");
    }

    println!("{:<34} {:<45}", "TAG", "VALUE");
    for t in i.tags.iter() {
        let k = if let Some(k) = t.key.as_deref() {
            k
        } else {
            continue;
        };
        let v = t.value.as_deref().unwrap_or("-");

        println!("{:<34} {:<45}", k, v);
    }

    Ok(())
}

async fn info(mut l: Level<Stuff>) -> Result<()> {
    // XXX l.optmulti("T", "", "specify a tag as an extra column", "TAG");

    l.add_column("launch", 24, false);
    l.add_column("id", 19, true);
    l.add_column("name", 28, true);
    l.add_column("ip", 15, true);
    l.add_column("state", 16, true);
    l.add_column("type", 12, false);
    // XXX for tag in s.args.opt_strs("T") {
    // XXX     l.add_column(&tag, 20, true);
    // XXX }

    let a = args!(l);
    let mut t = a.table();

    if !a.args().is_empty() {
        for n in a.args().iter() {
            let i = get_instance_fuzzy(l.context(), n).await?;

            let mut r = Row::default();
            r.add_str("id", &i.id);
            r.add_stror("name", &i.name, "-");
            r.add_str("launch", &i.launch);
            r.add_stror("ip", &i.ip, "-");
            r.add_str("state", &i.state);
            // XXX for tag in s.args.opt_strs("T") {
            // XXX     r.add_str(&tag, "-"); /* XXX */
            // XXX }
            t.add_row(r);
        }
    } else {
        let s = l.context();

        let res = s
            .ec2()
            .describe_instances(ec2::DescribeInstancesRequest {
                ..Default::default()
            })
            .await?;

        if let Some(r) = &res.reservations {
            for r in r.iter() {
                if let Some(i) = &r.instances {
                    for i in i.iter() {
                        let mut r = Row::default();

                        let pubip = i.public_ip_address.as_deref();
                        let privip = i.private_ip_address.as_deref();

                        r.add_stror("type", &i.instance_type, "-");
                        r.add_str("id", i.instance_id.as_deref().unwrap());
                        r.add_stror("name", &i.tags.tag("Name"), "-");
                        r.add_str("launch", i.launch_time.as_deref().unwrap());
                        r.add_str("ip", pubip.unwrap_or(privip.unwrap_or("-")));
                        r.add_str(
                            "state",
                            i.state.as_ref().unwrap().name.as_deref().unwrap(),
                        );

                        // XXX for tag in s.args.opt_strs("T") {
                        // XXX     r.add_stror(&tag, &i.tags.tag(&tag), "-");
                        // XXX }

                        t.add_row(r);
                    }
                }
            }
        }
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn start(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);
    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("starting instance: {:?}", i);

    start_instance(l.context(), &i.id).await?;

    println!("all done!");

    Ok(())
}

async fn nmi(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("sending diagnostic interrupt to instance: {:?}", i);

    s.ec2()
        .send_diagnostic_interrupt(ec2::SendDiagnosticInterruptRequest {
            instance_id: i.id.to_string(),
            ..Default::default()
        })
        .await?;

    println!("all done!");

    Ok(())
}

async fn sercons(mut l: Level<Stuff>) -> Result<()> {
    l.optflag("S", "start", "start the instance before we try to connect");

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let start = a.opts().opt_present("start");

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    /*
     * To access an EC2 serial console, you must first push an SSH key to the
     * remote system.  That key will be useable for 60 seconds to initiate an
     * SSH connection to the concentrator service.  At time of writing, the
     * serial console service only supports RSA keys; no other types.
     *
     * To make this easier, we will generate an ephemeral key and
     * tell ssh(1) about it.  Regrettably EC2 Instance Connect requires a
     * 2048 bit key, even though it has a 60 second lifetime and a 1024 bit key,
     * which would be substantially cheaper to generate, would seem fine.
     * The API is also very picky about how many times you can push a key,
     * even the same key, often throwing an error like "Too many active serial
     * console sessions." which is neither helpful nor even strictly true.
     *
     * We know the expected SSH host key for at least some of the servers, so we
     * can prepopulate a special known_hosts file.
     */
    let dir = if let Some(mut dir) = dirs_next::cache_dir() {
        dir.push("aws-wire-lengths");
        dir
    } else {
        bail!("could not find user cache directory");
    };
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&dir)?;

    let path_knownhosts = {
        let mut path_knownhosts = dir.clone();
        path_knownhosts.push("known_hosts");
        path_knownhosts
    };

    let lines = match std::fs::File::open(&path_knownhosts) {
        Ok(mut f) => {
            let mut s = String::new();
            f.read_to_string(&mut s)?;
            s.lines().map(|s| s.to_string()).collect::<Vec<_>>()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => bail!("opening {:?}: {:?}", path_knownhosts, e),
    };

    /*
     * The list of known hosts and their keys is included in the executable at
     * build time:
     */
    for want in include_str!("../known_hosts.txt").lines() {
        if lines.iter().any(|l| l == want) {
            /*
             * This key already appears in our local file.
             */
            continue;
        }

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&path_knownhosts)?;
        f.write_all(format!("{}\n", want).as_bytes())?;
        f.flush()?;
    }

    /*
     * Check to see if we have already generated an SSH key.  We will avoid
     * regenerating the key if it was generated in the last hour.
     */
    let path_pemfile = {
        let mut path_pemfile = dir.clone();
        path_pemfile.push("sercons.pem");
        path_pemfile
    };

    let key = match std::fs::File::open(&path_pemfile) {
        Ok(mut f) => {
            let mut s = String::new();
            if let Err(e) = f.read_to_string(&mut s) {
                eprintln!("WARNING: reading {:?}: {:?}", path_pemfile, e);
                None
            } else {
                match rsa::RsaPrivateKey::from_pkcs8_pem(&s) {
                    Ok(key) => {
                        if let Ok(age) = std::time::SystemTime::now()
                            .duration_since(f.metadata()?.modified()?)
                        {
                            if age.as_secs() < 3600 {
                                Some(key)
                            } else {
                                /*
                                 * Old key, so regenerate.
                                 */
                                None
                            }
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "WARNING: parsing {:?}: {:?}",
                            path_pemfile, e
                        );
                        None
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            eprintln!("WARNING: opening {:?}: {:?}", path_pemfile, e);
            None
        }
    };

    let key = if let Some(key) = key {
        key
    } else {
        eprintln!("INFO: generating a new SSH key...");
        let key = rsa::RsaPrivateKey::new(&mut thread_rng(), 2048)?;
        let privkey = key.to_pkcs8_pem()?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path_pemfile)?;
        f.write_all(privkey.to_string().as_bytes())?;
        f.flush()?;
        key
    };

    /*
     * Could not see an easy crate for emitting the OpenSSH style public key
     * format, so we'll do it here by hand.
     *
     * The format is:
     *
     *  string  "ssh-rsa"
     *  bigint  e
     *  bigint  n
     *
     * Both data types are length-prefixed with a network order 32-bit unsigned
     * integer, and then just consist of the bytes of the string or the network
     * ordered bytes of the integer.  This packed binary layout is then
     * base64-encoded.
     *
     * Note that we add an extra 0 on the significant end of the "n" field, in
     * order that it not be mis-interpreted as a very large and very negative
     * value.
     */
    let pubkey = key.to_public_key();
    let mut raw = Vec::<u8>::new();
    let hdr = "ssh-rsa";
    raw.extend_from_slice(&(hdr.as_bytes().len() as u32).to_be_bytes());
    raw.extend_from_slice(hdr.as_bytes());

    let e = pubkey.e().to_bytes_be();
    raw.extend_from_slice(&(e.len() as u32).to_be_bytes());
    raw.extend_from_slice(&e);

    let n = pubkey.n().to_bytes_be();
    raw.extend_from_slice(&((n.len() as u32) + 1).to_be_bytes());
    raw.push(0);
    raw.extend_from_slice(&n);

    let pubkey =
        format!("ssh-rsa {}", base64::encode_config(raw, base64::STANDARD));

    if start {
        start_instance(s, &i.id).await?;
    }

    /*
     * Try to push the key to the server.
     */
    let mut warned = false;
    let mut nostartmsg = false;
    loop {
        use ec2ic::SendSerialConsoleSSHPublicKeyError::*;

        match s
            .ic()
            .send_serial_console_ssh_public_key(
                ec2ic::SendSerialConsoleSSHPublicKeyRequest {
                    instance_id: i.id.to_string(),
                    ssh_public_key: pubkey.to_string(),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(x) => {
                if !x.success.unwrap_or_default() {
                    /*
                     * This is a bad API and it should feel bad.
                     */
                    eprintln!("WARNING: key push request did not succeed?");
                }
                break;
            }
            Err(RusotoError::Service(Throttling(e))) => {
                /*
                 * Sigh.
                 */
                eprintln!("WARNING: throttle? {}", e);
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(RusotoError::Unknown(res)) => {
                let b = res.body_as_str();

                if res.status == 400
                    && (b.contains("stopped instance")
                        || b.contains("pending state"))
                {
                    /*
                     * This looks like the instance is not started.  So that we
                     * can try to catch it as soon as possible in boot, poll
                     * waiting for it to start.
                     */
                    if !nostartmsg {
                        eprintln!(
                            "INFO: instance not running? waiting to start..."
                        );
                        nostartmsg = true;
                    }

                    std::thread::sleep(Duration::from_secs(1));
                } else {
                    bail!("SSH key push failure: {}", res.body_as_str());
                }
            }
            Err(RusotoError::Service(SerialConsoleSessionLimitExceeded(e))) => {
                if !warned {
                    eprintln!("WARNING: {} (retrying)", e);
                    warned = true;
                }

                std::thread::sleep(Duration::from_secs(3));
            }
            Err(e) => {
                bail!("SSH key push failure: {:?}", e);
            }
        }
    }

    if warned || nostartmsg {
        println!();
    }

    println!("Connecting to serial console.  Escape sequence is <Enter>#.");
    let err = std::process::Command::new("ssh")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            path_knownhosts.to_str().unwrap()
        ))
        .arg("-e")
        .arg("#")
        .arg("-i")
        .arg(path_pemfile)
        .arg(format!(
            "{}.port0@serial-console.ec2-instance-connect.{}.aws",
            i.id,
            s.region_ec2().name()
        ))
        .exec();

    bail!("SSH exec error: {:?}", err);
}

async fn stop(mut l: Level<Stuff>) -> Result<()> {
    l.optflag("f", "", "force stop");

    let a = args!(l);

    let force = a.opts().opt_present("f");

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("stopping instance: {:?}", i);

    stop_instance(l.context(), &i.id, force).await?;

    println!("all done!");

    Ok(())
}

async fn reboot(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("rebooting instance: {:?}", i);

    s.ec2()
        .reboot_instances(ec2::RebootInstancesRequest {
            instance_ids: vec![i.id.to_string()],
            ..Default::default()
        })
        .await?;

    println!("all done!");

    Ok(())
}

async fn protect(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("protecting instance: {:?}", i);

    protect_instance(l.context(), &i.id, true).await?;

    println!("all done!");

    Ok(())
}

async fn unprotect(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("unprotecting instance: {:?}", i);

    protect_instance(l.context(), &i.id, false).await?;

    println!("all done!");

    Ok(())
}

async fn destroy(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("destroying instance: {:?}", i);

    destroy_instance(l.context(), &i.id).await?;

    println!("all done!");

    Ok(())
}

async fn do_role_assume(mut l: Level<Stuff>) -> Result<()> {
    l.reqopt("", "role", "ARN of role to assume", "ARN");
    l.reqopt("", "session", "name of session", "NAME");
    l.reqopt("", "mfa", "ARN of MFA token", "SERIAL");
    l.reqopt("", "token", "MFA token code", "CODE");
    l.optflag("", "shell", "emit shell commands to configure environment");

    let a = no_args!(l);

    let res = l
        .context()
        .sts()
        .assume_role(AssumeRoleRequest {
            duration_seconds: Some(3600),
            role_arn: a.opts().opt_str("role").unwrap(),
            role_session_name: a.opts().opt_str("session").unwrap(),
            serial_number: a.opts().opt_str("mfa"),
            token_code: a.opts().opt_str("token"),
            ..Default::default()
        })
        .await?;

    if a.opts().opt_present("shell") {
        if let Some(c) = res.credentials {
            println!("AWS_ACCESS_KEY_ID='{}'; ", c.access_key_id);
            println!("AWS_CREDENTIAL_EXPIRATION='{}'; ", c.expiration);
            println!("AWS_SECRET_ACCESS_KEY='{}'; ", c.secret_access_key);
            println!("AWS_SESSION_TOKEN='{}'; ", c.session_token);
            for v in [
                "ACCESS_KEY_ID",
                "CREDENTIAL_EXPIRATION",
                "SECRET_ACCESS_KEY",
                "SESSION_TOKEN",
            ] {
                println!("export AWS_{}; ", v);
            }
        }
    } else {
        println!("res: {:#?}", res);
    }
    Ok(())
}

// async fn register_image(mut l: Level<Stuff>) -> Result<()> {
//     let name = s.args.opt_str("n").unwrap();
//     let snapid = s.args.opt_str("s").unwrap();
//     let support_ena = s.args.opt_present("E");
//
//     let imageid = i_register_image(s, &name, &snapid, support_ena).await?;
//     println!("COMPLETED IMAGE ID: {}", imageid);
//
//     Ok(())
// }

async fn i_register_image(
    s: &Stuff,
    name: &str,
    snapid: &str,
    ena: bool,
) -> Result<String> {
    let res = s
        .ec2()
        .describe_snapshots(DescribeSnapshotsRequest {
            snapshot_ids: Some(vec![snapid.to_string()]),
            ..Default::default()
        })
        .await?;
    let snap = res.snapshots.unwrap().get(0).unwrap().clone();

    let res = s
        .ec2()
        .register_image(RegisterImageRequest {
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
                    device_name: ss("/dev/sdb"),    /* XXX? */
                    virtual_name: ss("ephemeral0"), /* XXX? */
                    ..Default::default()
                },
                BlockDeviceMapping {
                    device_name: ss("/dev/sdc"),    /* XXX? */
                    virtual_name: ss("ephemeral1"), /* XXX? */
                    ..Default::default()
                },
                BlockDeviceMapping {
                    device_name: ss("/dev/sdd"),    /* XXX? */
                    virtual_name: ss("ephemeral2"), /* XXX? */
                    ..Default::default()
                },
                BlockDeviceMapping {
                    device_name: ss("/dev/sde"),    /* XXX? */
                    virtual_name: ss("ephemeral3"), /* XXX? */
                    ..Default::default()
                },
            ]),
            ..Default::default()
        })
        .await?;

    println!("res: {:#?}", res);

    let imageid = res.image_id.unwrap();
    println!("IMAGE ID: {}", snapid);

    loop {
        let res = s
            .ec2()
            .describe_images(DescribeImagesRequest {
                image_ids: Some(vec![imageid.to_string()]),
                ..Default::default()
            })
            .await?;

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

#[derive(Default)]
struct Stuff {
    region_ec2: Region,
    region_s3: Region,
    region_sts: Region,
    s3: Option<s3::S3Client>,
    ec2: Option<ec2::Ec2Client>,
    ic: Option<ec2ic::Ec2InstanceConnectClient>,
    sts: Option<sts::StsClient>,
    credprov: Option<Box<dyn ProvideAwsCredentials + Send + Sync>>,
}

#[allow(dead_code)]
impl Stuff {
    fn ec2(&self) -> &dyn Ec2 {
        self.ec2.as_ref().unwrap()
    }

    fn s3(&self) -> &dyn S3 {
        self.s3.as_ref().unwrap()
    }

    fn sts(&self) -> &dyn Sts {
        self.sts.as_ref().unwrap()
    }

    fn ic(&self) -> &dyn Ec2InstanceConnect {
        self.ic.as_ref().unwrap()
    }

    fn region_ec2(&self) -> &Region {
        &self.region_ec2
    }

    fn region_s3(&self) -> &Region {
        &self.region_s3
    }

    fn region_sts(&self) -> &Region {
        &self.region_sts
    }

    fn credprov(&self) -> &dyn ProvideAwsCredentials {
        self.credprov.as_deref().unwrap()
    }
}

async fn do_instance(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list instances", cmd!(info))?;
    l.hcmd("dump", "dump info about an instance", cmd!(dump))?;
    l.cmd("ip", "get IP address for instance", cmd!(ip))?;
    l.cmd("start", "start an instance", cmd!(start))?;
    l.cmd("reboot", "reboot an instance", cmd!(reboot))?;
    l.cmd("stop", "stop an instance", cmd!(stop))?;
    l.cmd("protect", "enable termination protection", cmd!(protect))?;
    l.cmd(
        "unprotect",
        "disable termination protection",
        cmd!(unprotect),
    )?;
    l.cmd("create", "create an instance", cmd!(create_instance))?;
    l.cmd("destroy", "destroy an instance", cmd!(destroy))?;
    l.cmda(
        "diag",
        "nmi",
        "send diagnostic interrupt to instance",
        cmd!(nmi),
    )?;
    l.cmd(
        "console",
        "connect to the serial console of a guest",
        cmd!(sercons),
    )?;

    sel!(l).run().await
}

async fn do_volume(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list volumes", cmd!(volumes))?; /* XXX */
    l.cmda("destroy", "rm", "destroy a volume", cmd!(do_volume_rm))?;

    sel!(l).run().await
}

async fn do_snapshot(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list snapshots", cmd!(snapshots))?; /* XXX */
    l.cmda("destroy", "rm", "destroy a snapshot", cmd!(do_snapshot_rm))?;

    sel!(l).run().await
}

async fn do_role(mut l: Level<Stuff>) -> Result<()> {
    l.cmd("assume", "assume a role", cmd!(do_role_assume))?;

    sel!(l).run().await
}

async fn do_image(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list images", cmd!(images))?; /* XXX */
    l.cmda("destroy", "rm", "destroy an image", cmd!(do_image_rm))?;
    l.cmd(
        "publish",
        "publish a raw file as an AMI",
        cmd!(ami_from_file),
    )?;

    sel!(l).run().await
}

async fn do_key(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list SSH keys", cmd!(do_key_ls))?;
    l.cmd("create", "create new SSH key", cmd!(do_key_create))?;
    l.cmda("destroy", "rm", "destroy an SSH key", cmd!(do_key_rm))?;

    sel!(l).run().await
}

async fn do_key_rm(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("KEYNAME..."));

    let a = args!(l);
    let s = l.context();

    if a.args().is_empty() {
        bail!("specify which key name(s) to delete");
    }

    for name in a.args().iter() {
        s.ec2()
            .delete_key_pair(ec2::DeleteKeyPairRequest {
                key_name: Some(name.to_string()),
                ..Default::default()
            })
            .await?;
        println!("deleted {}", name);
    }

    Ok(())
}

async fn do_key_create(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("KEYNAME"));
    l.reqopt("o", "", "output file name for created key", "PEMFILE");

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bail!("just one key name");
    }

    /*
     * Open the target file without overwriting an existing file.
     */
    let path = a.opts().opt_str("o").unwrap();
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;

    let key_name = a.args().get(0).unwrap().to_string();

    let res = s
        .ec2()
        .create_key_pair(ec2::CreateKeyPairRequest {
            key_name,
            ..Default::default()
        })
        .await?;

    if let Some(mat) = res.key_material.as_deref() {
        f.write_all(mat.as_bytes())?;
        f.flush()?;
    } else {
        bail!("no key material in response: {:#?}", res);
    }

    if let Some(fp) = res.key_fingerprint.as_deref() {
        eprintln!("fingerprint = {}", fp);
    }

    Ok(())
}

async fn do_key_ls(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("name", 20, true);
    l.add_column("fingerprint", 59, true);
    l.add_column("id", 21, false);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s
        .ec2()
        .describe_key_pairs(ec2::DescribeKeyPairsRequest {
            ..Default::default()
        })
        .await?;

    let x = Vec::new();
    for kp in res.key_pairs.as_ref().unwrap_or(&x) {
        let mut r = Row::default();

        r.add_stror("id", &kp.key_pair_id, "?");
        r.add_stror("name", &kp.key_name, "-");
        r.add_stror("fingerprint", &kp.key_fingerprint, "-");

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn do_sg(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list security groups", cmd!(do_sg_ls))?;

    sel!(l).run().await
}

async fn do_sg_ls(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", 20, true);
    l.add_column("name", 28, true);
    l.add_column("vpc", 21, true);
    l.add_column("desc", 32, false);
    l.add_column("fulldesc", 50, false);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s
        .ec2()
        .describe_security_groups(ec2::DescribeSecurityGroupsRequest {
            ..Default::default()
        })
        .await?;

    let x = Vec::new();
    for sg in res.security_groups.as_ref().unwrap_or(&x) {
        let mut r = Row::default();

        r.add_stror("id", &sg.group_id, "?");
        r.add_stror("name", &sg.group_name, "-");
        r.add_stror("vpc", &sg.vpc_id, "-");
        let desc = if let Some(desc) = sg.description.as_deref() {
            if let Some(name) = sg.group_name.as_deref() {
                desc.trim_start_matches(name)
            } else {
                desc
            }
            .trim()
        } else {
            "-"
        };
        r.add_str("desc", desc);
        r.add_stror("fulldesc", &sg.description, "-");

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn do_serial_disable(mut l: Level<Stuff>) -> Result<()> {
    no_args!(l);
    let s = l.context();

    let res = s
        .ec2()
        .disable_serial_console_access(
            ec2::DisableSerialConsoleAccessRequest::default(),
        )
        .await?;

    if res
        .serial_console_access_enabled
        .ok_or_else(|| anyhow!("weird response"))?
    {
        bail!("tried to disable serial consoles, but they are still enabled");
    }

    Ok(())
}

async fn do_serial_enable(mut l: Level<Stuff>) -> Result<()> {
    no_args!(l);
    let s = l.context();

    let res = s
        .ec2()
        .enable_serial_console_access(
            ec2::EnableSerialConsoleAccessRequest::default(),
        )
        .await?;

    if !res
        .serial_console_access_enabled
        .ok_or_else(|| anyhow!("weird response"))?
    {
        bail!("tried to enable serial consoles, but they are still disabled");
    }

    Ok(())
}

async fn do_serial_get(mut l: Level<Stuff>) -> Result<()> {
    no_args!(l);
    let s = l.context();

    let res = s
        .ec2()
        .get_serial_console_access_status(
            ec2::GetSerialConsoleAccessStatusRequest::default(),
        )
        .await?;

    if res
        .serial_console_access_enabled
        .ok_or_else(|| anyhow!("weird response"))?
    {
        println!("enabled");
    } else {
        println!("disabled");
    }

    Ok(())
}

async fn do_serial(mut l: Level<Stuff>) -> Result<()> {
    l.cmda(
        "enable",
        "on",
        "enable serial consoles",
        cmd!(do_serial_enable),
    )?;
    l.cmda(
        "disable",
        "off",
        "disable serial consoles",
        cmd!(do_serial_disable),
    )?;
    l.cmd(
        "get",
        "get serial console enable status",
        cmd!(do_serial_get),
    )?;

    sel!(l).run().await
}

async fn do_config(mut l: Level<Stuff>) -> Result<()> {
    l.cmd("serial", "manage serial console access", cmd!(do_serial))?;

    sel!(l).run().await
}

async fn do_subnet(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list subnets", cmd!(do_subnet_ls))?;

    sel!(l).run().await
}

async fn do_subnet_ls(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", 24, true);
    l.add_column("name", 20, true);
    l.add_column("cidr", 18, true);
    l.add_column("az", 14, false);
    l.add_column("vpc", 21, false);
    l.add_column("flags", 5, true);
    l.add_column("avail", 5, true);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s
        .ec2()
        .describe_subnets(ec2::DescribeSubnetsRequest {
            ..Default::default()
        })
        .await?;

    let x = Vec::new();
    for sn in res.subnets.as_ref().unwrap_or(&x) {
        /*
         * Find the name tag value:
         */
        let nametag = if let Some(tags) = sn.tags.as_ref() {
            tags.iter()
                .find(|t| t.key.as_deref() == Some("Name"))
                .and_then(|t| t.value.as_deref())
                .map(|s| s.to_string())
        } else {
            None
        };

        let flags = [
            sn.map_public_ip_on_launch.as_flag("P"),
            sn.default_for_az.as_flag("D"),
        ]
        .join("");

        let mut r = Row::default();

        r.add_stror("id", &sn.subnet_id, "?");
        r.add_stror("vpc", &sn.vpc_id, "-");
        r.add_stror("cidr", &sn.cidr_block, "-");
        r.add_stror("name", &nametag, "-");
        r.add_stror("az", &sn.availability_zone, "-");
        r.add_str("flags", &flags);
        r.add_u64("avail", sn.available_ip_address_count.unwrap_or(0) as u64);

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut l = Level::new("aws-wire-lengths", Stuff::default());

    l.optflag("e", "", "use environment variables for credentials");
    l.optopt("r", "region-ec2", "region for EC2", "REGION");
    l.optopt("R", "region-s3", "region for S3", "REGION");
    l.optopt("", "region-sts", "region for STS", "REGION");

    l.cmda("instance", "inst", "instance management", cmd!(do_instance))?;
    l.cmda("volume", "vol", "volume management", cmd!(do_volume))?;
    l.cmda("snapshot", "snap", "snapshot management", cmd!(do_snapshot))?;
    l.cmda("image", "ami", "image (AMI) management", cmd!(do_image))?;
    l.cmd(
        "role",
        "security token service (STS) management",
        cmd!(do_role),
    )?;
    l.cmd("sg", "security group management", cmd!(do_sg))?;
    l.cmd("key", "SSH key management", cmd!(do_key))?;
    l.cmd("subnet", "subnet management", cmd!(do_subnet))?;
    l.cmd(
        "config",
        "manage account- or region-level configuration",
        cmd!(do_config),
    )?;
    /*
     * XXX These are used in some scripts, so leave them (but hidden) for now.
     */
    l.hcmd(
        "ami-from-file",
        "COMPAT: AMI from file",
        cmd!(ami_from_file),
    )?;
    l.hcmd("everything", "COMPAT: AMI from file", cmd!(ami_from_file))?;

    //  let f: Caller = match std::env::args().nth(1).as_deref() {
    //        Some("put-object") => {
    //            opts.reqopt("b", "bucket", "S3 bucket", "BUCKET");
    //            opts.reqopt("o", "object", "S3 object name", "OBJECT");
    //            opts.reqopt("f", "file", "local file to upload", "FILENAME");
    //
    //            |s| Box::pin(put_object(s))
    //        }
    //        Some("import-volume") => {
    //            opts.reqopt("b", "bucket", "S3 bucket", "BUCKET");
    //            opts.reqopt("p", "prefix", "S3 prefix", "PREFIX");
    //
    //            |s| Box::pin(import_volume(s))
    //        }
    //        Some("create-snapshot") => {
    //            opts.reqopt("v", "volume", "volume ID to snapshot", "VOLUME_ID");
    //
    //            |s| Box::pin(create_snapshot(s))
    //        }
    //        Some("register-image") => {
    //            opts.reqopt("s", "snapshot", "snapshot ID to register",
    //                "SNAPSHOT_ID");
    //            opts.reqopt("n", "name", "target image name", "NAME");
    //            opts.optflag("E", "ena", "enable ENA support");
    //
    //            |s| Box::pin(register_image(s))
    //        }
    //        cmd => bail!("invalid command {:?}", cmd),
    //    };

    /*
     * Parse arguments and select which command we will be running.
     */
    let mut s = sel!(l);

    s.context_mut().credprov = Some(if s.opts().opt_present("e") {
        Box::new(EnvironmentProvider::default())
    } else {
        Box::new(DefaultCredentialsProvider::new()?)
    });

    if let Some(reg) = s.opts().opt_str("region-s3").as_deref() {
        s.context_mut().region_s3 =
            Region::from_str(reg).context("invalid S3 region")?;
    };
    if let Some(reg) = s.opts().opt_str("region-ec2").as_deref() {
        s.context_mut().region_ec2 =
            Region::from_str(reg).context("invalid EC2 region")?;
    };
    if let Some(reg) = s.opts().opt_str("region-sts").as_deref() {
        s.context_mut().region_sts =
            Region::from_str(reg).context("invalid STS region")?;
    };

    if s.opts().opt_present("e") {
        let mut stuff = s.context_mut();
        stuff.s3 = Some(S3Client::new_with(
            HttpClient::new()?,
            EnvironmentProvider::default(),
            stuff.region_s3.clone(),
        ));
        stuff.ec2 = Some(Ec2Client::new_with(
            HttpClient::new()?,
            EnvironmentProvider::default(),
            stuff.region_ec2.clone(),
        ));
        stuff.ic = Some(Ec2InstanceConnectClient::new_with(
            HttpClient::new()?,
            EnvironmentProvider::default(),
            stuff.region_ec2.clone(),
        ));
        stuff.sts = Some(StsClient::new_with(
            HttpClient::new()?,
            EnvironmentProvider::default(),
            stuff.region_sts.clone(),
        ));
    } else {
        let mut stuff = s.context_mut();
        stuff.s3 = Some(S3Client::new_with(
            HttpClient::new()?,
            DefaultCredentialsProvider::new()?,
            stuff.region_s3.clone(),
        ));
        stuff.ec2 = Some(Ec2Client::new_with(
            HttpClient::new()?,
            DefaultCredentialsProvider::new()?,
            stuff.region_ec2.clone(),
        ));
        stuff.ic = Some(Ec2InstanceConnectClient::new_with(
            HttpClient::new()?,
            DefaultCredentialsProvider::new()?,
            stuff.region_ec2.clone(),
        ));
        stuff.sts = Some(StsClient::new_with(
            HttpClient::new()?,
            DefaultCredentialsProvider::new()?,
            stuff.region_sts.clone(),
        ));
    };

    s.run().await
}

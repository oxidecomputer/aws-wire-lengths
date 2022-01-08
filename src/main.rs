/*
 * Copyright 2021 Oxide Computer Company
 */

#![allow(clippy::many_single_char_names)]

use anyhow::{anyhow, bail, Context, Result};
use bytes::BytesMut;
use ec2::{
    BlockDeviceMapping, CreateSnapshotRequest, DeleteVolumeRequest,
    DescribeConversionTasksRequest, DescribeImagesRequest,
    DescribeSnapshotsRequest, DiskImageDetail, EbsBlockDevice, Ec2, Ec2Client,
    ImportVolumeRequest, InstanceNetworkInterfaceSpecification,
    RegisterImageRequest, RunInstancesRequest, Tag, TagSpecification,
    VolumeDetail,
};
use ec2ic::{Ec2InstanceConnect, Ec2InstanceConnectClient};
use hiercmd::prelude::*;
use rusoto_core::param::Params;
use rusoto_core::signature::SignedRequest;
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
use std::str::FromStr;
use std::time::Duration;
use sts::{Sts, StsClient};
use xml::writer::{EmitterConfig, EventWriter, XmlEvent};

mod util;

mod prelude {
    pub(crate) use std::collections::HashMap;
    pub(crate) use std::fs::File;
    pub(crate) use std::io::{Read, Write};
    pub(crate) use std::os::unix::fs::DirBuilderExt;
    pub(crate) use std::os::unix::prelude::*;
    pub(crate) use std::time::Duration;

    #[allow(unused_imports)]
    pub(crate) use anyhow::{anyhow, bail, Context, Result};
    pub(crate) use bytes::BytesMut;
    pub(crate) use hiercmd::prelude::*;
    pub(crate) use rand::thread_rng;
    pub(crate) use rsa::pkcs8::{FromPrivateKey, ToPrivateKey};
    pub(crate) use rsa::PublicKeyParts;
    pub(crate) use rusoto_core::RusotoError;
    pub(crate) use rusoto_ec2 as ec2;
    pub(crate) use rusoto_ec2_instance_connect as ec2ic;
    pub(crate) use rusoto_s3 as s3;
    pub(crate) use rusoto_sts as sts;
    pub(crate) use tokio::io::AsyncReadExt;

    pub(crate) use super::util::*;
    pub(crate) use super::{
        destroy_instance, get_instance, get_instance_fuzzy, get_rt_fuzzy,
        get_sg_fuzzy, get_vpc_fuzzy, i_create_instance, i_create_snapshot,
        i_import_volume, i_put_object, i_register_image, i_volume_rm,
        protect_instance, start_instance, stop_instance,
    };
    pub(crate) use super::{InstanceLookup, InstanceOptions, Stuff};
}

mod cmd;
use cmd::config::do_config;
use cmd::image::{ami_from_file, do_image};
use cmd::instance::do_instance;
use cmd::key::do_key;
use cmd::role::do_role;
use cmd::route::do_route;
use cmd::s3::do_s3;
use cmd::sg::do_sg;
use cmd::snapshot::do_snapshot;
use cmd::subnet::do_subnet;
use cmd::type_::do_type;
use cmd::volume::do_volume;
use cmd::vpc::do_vpc;

use util::*;

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

fn one_ping_only<T>(noun: &str, filter: &str, v: Option<Vec<T>>) -> Result<T> {
    if let Some(mut v) = v {
        if v.len() == 1 {
            return Ok(v.pop().unwrap());
        }

        if v.len() > 1 {
            bail!("more than one {} matched filter \"{}\"", noun, filter);
        }
    }

    bail!("could not find a {} matching \"{}\"", noun, filter);
}

async fn get_vpc_fuzzy(s: &Stuff, lookuparg: &str) -> Result<ec2::Vpc> {
    let filters = Some(if lookuparg.starts_with("vpc-") {
        vec![ec2::Filter {
            name: Some("vpc-id".to_string()),
            values: Some(vec![lookuparg.into()]),
        }]
    } else {
        vec![ec2::Filter {
            name: Some("tag:Name".to_string()),
            values: Some(vec![lookuparg.into()]),
        }]
    });

    let res = s
        .ec2()
        .describe_vpcs(ec2::DescribeVpcsRequest {
            filters,
            ..Default::default()
        })
        .await?;

    one_ping_only("VPC", lookuparg, res.vpcs)
}

async fn get_rt_fuzzy(
    s: &Stuff,
    lookuparg: &str,
    direct_only: bool,
) -> Result<ec2::RouteTable> {
    let filters = Some(if lookuparg.starts_with("rtb-") {
        vec![ec2::Filter {
            name: Some("route-table-id".to_string()),
            values: Some(vec![lookuparg.into()]),
        }]
    } else if !direct_only && lookuparg.starts_with("vpc-") {
        vec![
            ec2::Filter {
                name: Some("vpc-id".to_string()),
                values: Some(vec![lookuparg.into()]),
            },
            ec2::Filter {
                name: Some("association.main".to_string()),
                values: Some(vec!["true".to_string()]),
            },
        ]
    } else if !direct_only && lookuparg.starts_with("subnet-") {
        vec![ec2::Filter {
            name: Some("association.subnet-id".to_string()),
            values: Some(vec![lookuparg.into()]),
        }]
    } else {
        vec![ec2::Filter {
            name: Some("tag:Name".to_string()),
            values: Some(vec![lookuparg.into()]),
        }]
    });

    let res = s
        .ec2()
        .describe_route_tables(ec2::DescribeRouteTablesRequest {
            filters,
            ..Default::default()
        })
        .await?;

    one_ping_only("route table", lookuparg, res.route_tables)
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
                        .map(|o| o.to_vec())
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

async fn i_volume_rm(s: &Stuff, volid: &str, dry_run: bool) -> Result<()> {
    s.ec2()
        .delete_volume(DeleteVolumeRequest {
            dry_run: Some(dry_run),
            volume_id: volid.to_string(),
        })
        .await?;
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
pub struct Stuff {
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
    l.cmd("vpc", "VPC management", cmd!(do_vpc))?;
    l.cmd("subnet", "subnet management", cmd!(do_subnet))?;
    l.cmda("route", "rt", "routing table management", cmd!(do_route))?;
    l.cmd(
        "config",
        "manage account- or region-level configuration",
        cmd!(do_config),
    )?;
    l.cmd("type", "instance type management", cmd!(do_type))?;
    l.cmda("s3", "s", "S3 object storage", cmd!(do_s3))?;
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

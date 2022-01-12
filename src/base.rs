use std::fs::File;
use std::io::{Read, Write};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use bytes::BytesMut;
use rusoto_core::param::Params;
use rusoto_core::Region;
use rusoto_ec2 as ec2;
use rusoto_s3 as s3;
use xml::writer::{EmitterConfig, EventWriter, XmlEvent};

use ec2::{
    BlockDeviceMapping, CreateSnapshotRequest, DeleteVolumeRequest,
    DescribeConversionTasksRequest, DescribeImagesRequest,
    DescribeSnapshotsRequest, DiskImageDetail, EbsBlockDevice,
    ImportVolumeRequest, RegisterImageRequest, Tag, VolumeDetail,
};
use s3::util::PreSignedRequest;
use s3::{
    CompleteMultipartUploadRequest, CompletedMultipartUpload, CompletedPart,
    CreateMultipartUploadRequest, DeleteObjectRequest, GetObjectRequest,
    HeadObjectRequest, PutObjectRequest, UploadPartRequest, S3,
};

use crate::util::*;
use crate::Stuff;

#[derive(Debug)]
pub struct Instance {
    pub name: Option<String>,
    pub id: String,
    pub ip: Option<String>,
    pub state: String,
    pub launch: String,
    pub tags: Vec<Tag>,
    pub nics: Vec<String>,
    pub az: Option<String>,
}

#[derive(Debug, Clone)]
pub enum InstanceLookup {
    ById(String),
    ByName(String),
}

pub async fn start_instance(s: &Stuff, id: &str) -> Result<()> {
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

pub async fn stop_instance(s: &Stuff, id: &str, force: bool) -> Result<()> {
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

pub async fn instance_spoofing(s: &Stuff, id: &str, spoof: bool) -> Result<()> {
    println!("setting spoofing to {} on instance {}...", spoof, id);

    /*
     * If we want to allow spoofing, disable the source/destination check:
     */
    let source_dest_check = Some(ec2::AttributeBooleanValue {
        value: Some(!spoof),
    });

    s.ec2()
        .modify_instance_attribute(ec2::ModifyInstanceAttributeRequest {
            instance_id: id.to_string(),
            source_dest_check,
            ..Default::default()
        })
        .await?;

    Ok(())
}

pub async fn protect_instance(s: &Stuff, id: &str, prot: bool) -> Result<()> {
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

pub async fn destroy_instance(s: &Stuff, id: &str) -> Result<()> {
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

pub async fn get_instance_fuzzy(
    s: &Stuff,
    lookuparg: &str,
) -> Result<Instance> {
    let lookup = if lookuparg.starts_with("i-") {
        InstanceLookup::ById(lookuparg.to_string())
    } else {
        InstanceLookup::ByName(lookuparg.to_string())
    };

    Ok(get_instance_x(s, lookup, true).await?)
}

pub async fn get_instance(
    s: &Stuff,
    lookup: InstanceLookup,
) -> Result<Instance> {
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
                    nics: inst
                        .network_interfaces
                        .as_ref()
                        .unwrap()
                        .iter()
                        .map(|nic| {
                            nic.network_interface_id
                                .as_ref()
                                .unwrap()
                                .to_string()
                        })
                        .collect(),
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
                    az: inst.placement.as_ref().map(|p| {
                        p.availability_zone.as_ref().unwrap().to_string()
                    }),
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

pub async fn get_vol_fuzzy(
    s: &Stuff,
    lookuparg: &str,
) -> Result<aws_sdk_ec2::model::Volume> {
    let res = s
        .more()
        .ec2()
        .describe_volumes()
        .filters(
            aws_sdk_ec2::model::Filter::builder()
                .name(if lookuparg.starts_with("vol-") {
                    "vol-id"
                } else {
                    "tag:Name"
                })
                .values(lookuparg)
                .build(),
        )
        .send()
        .await?;

    one_ping_only("volume", lookuparg, res.volumes)
}

pub async fn get_vpc_fuzzy(s: &Stuff, lookuparg: &str) -> Result<ec2::Vpc> {
    let filters = Some(if lookuparg.starts_with("vpc-") {
        vec![ec2::Filter {
            name: ss("vpc-id"),
            values: Some(vec![lookuparg.into()]),
        }]
    } else {
        vec![ec2::Filter {
            name: ss("tag:Name"),
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

pub async fn get_sg_fuzzy(
    s: &Stuff,
    lookuparg: &str,
) -> Result<ec2::SecurityGroup> {
    let filters = Some(if lookuparg.starts_with("sg-") {
        vec![ec2::Filter {
            name: ss("group-id"),
            values: Some(vec![lookuparg.into()]),
        }]
    } else {
        vec![ec2::Filter {
            name: ss("group-name"),
            values: Some(vec![lookuparg.into()]),
        }]
    });

    let res = s
        .ec2()
        .describe_security_groups(ec2::DescribeSecurityGroupsRequest {
            filters,
            ..Default::default()
        })
        .await?;

    one_ping_only("security group", lookuparg, res.security_groups)
}

pub async fn get_rt_fuzzy(
    s: &Stuff,
    lookuparg: &str,
    direct_only: bool,
) -> Result<ec2::RouteTable> {
    let filters = Some(if lookuparg.starts_with("rtb-") {
        vec![ec2::Filter {
            name: ss("route-table-id"),
            values: Some(vec![lookuparg.into()]),
        }]
    } else if !direct_only && lookuparg.starts_with("vpc-") {
        /*
         * Get the default route table for this VPC.
         */
        vec![
            ec2::Filter {
                name: ss("vpc-id"),
                values: Some(vec![lookuparg.into()]),
            },
            ec2::Filter {
                name: ss("association.main"),
                values: Some(vec!["true".to_string()]),
            },
        ]
    } else if !direct_only && lookuparg.starts_with("subnet-") {
        /*
         * Get the route table associated with this subnet, if there is one.  If
         * there is not, the default route table for the VPC applies, but for
         * now we are not looking for that here.
         */
        vec![ec2::Filter {
            name: ss("association.subnet-id"),
            values: Some(vec![lookuparg.into()]),
        }]
    } else {
        vec![ec2::Filter {
            name: ss("tag:Name"),
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

pub async fn filter_vpc_fuzzy(
    s: &Stuff,
    optarg: Option<String>,
) -> Result<Option<Vec<ec2::Filter>>> {
    if let Some(optarg) = optarg.as_deref() {
        let vpc = get_vpc_fuzzy(s, optarg).await?;
        Ok(Some(vec![ec2::Filter {
            name: ss("vpc-id"),
            values: Some(vec![vpc.vpc_id.unwrap()]),
        }]))
    } else {
        Ok(None)
    }
}

pub async fn i_import_volume(
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

pub async fn i_create_snapshot(s: &Stuff, volid: &str) -> Result<String> {
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

pub async fn i_register_image(
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

pub async fn i_volume_rm(s: &Stuff, volid: &str, dry_run: bool) -> Result<()> {
    s.ec2()
        .delete_volume(DeleteVolumeRequest {
            dry_run: Some(dry_run),
            volume_id: volid.to_string(),
        })
        .await?;
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

pub async fn i_put_object(
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

pub async fn sign_delete(
    c: &dyn rusoto_credential::ProvideAwsCredentials,
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
        &s3::util::PreSignedRequestOption {
            expires_in: Duration::from_secs(3600),
        },
    ))
}

pub async fn sign_head(
    c: &dyn rusoto_credential::ProvideAwsCredentials,
    r: &Region,
    b: &str,
    k: &str,
) -> Result<String> {
    let creds = c.credentials().await?;
    let uri = format!("/{}/{}", b, k);
    let mut req =
        rusoto_core::signature::SignedRequest::new("HEAD", "s3", r, &uri);
    let params = Params::new();

    let expires_in = Duration::from_secs(3600);

    req.set_params(params);
    Ok(req.generate_presigned_url(&creds, &expires_in, false))
}

pub async fn sign_get(
    c: &dyn rusoto_credential::ProvideAwsCredentials,
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
        &s3::util::PreSignedRequestOption {
            expires_in: Duration::from_secs(300),
        },
    ))
}

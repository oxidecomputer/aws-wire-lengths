use std::fs::File;
use std::io::{Read, Write};
use std::sync::Arc;

use anyhow::{bail, Result};
use aws_sdk_ebs::primitives::DateTimeFormat;
use aws_sdk_ec2::types::builders::AttributeValueBuilder;
use aws_sdk_ec2::types::{
    ArchitectureValues, AttributeBooleanValue, BlockDeviceMapping,
    EbsBlockDevice, Filter, InstanceStateName, SecurityGroup, Tag, VolumeType,
};
use sha2::Digest;

use crate::util::*;
use crate::Stuff;

#[derive(Debug)]
pub struct Instance {
    pub name: Option<String>,
    pub id: String,
    pub ip: Option<String>,
    pub state: InstanceStateName,
    pub launch: String,
    pub tags: Vec<Tag>,
    pub nics: Vec<String>,
    pub az: Option<String>,
    pub raw: aws_sdk_ec2::types::Instance,
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
    let mut last_state = None;

    loop {
        let inst = get_instance(s, lookup.clone()).await?;

        let new_state = if let Some(last_state) = &last_state {
            last_state != &inst.state
        } else {
            true
        };

        if new_state {
            println!("    state is {}", inst.state.as_str());
            last_state = Some(inst.state.clone());
        }

        let shouldstart = match &inst.state {
            InstanceStateName::Terminated => {
                bail!("cannot start a terminated instance?");
            }
            n @ InstanceStateName::Running => {
                println!("    state is {}; done!", n.as_str());
                return Ok(());
            }
            InstanceStateName::Stopped => true,
            _ => false,
        };

        if shouldstart && !started {
            println!("    starting...");
            let res = s.ec2().start_instances().instance_ids(id).send().await?;
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
    let mut last_state = None;

    loop {
        let inst = get_instance(s, lookup.clone()).await?;

        let new_state = if let Some(last_state) = &last_state {
            last_state != &inst.state
        } else {
            true
        };

        if new_state {
            println!("    state is {}", inst.state.as_str());
            last_state = Some(inst.state.clone());
        }

        let shouldstop = match &inst.state {
            n @ InstanceStateName::Stopped => {
                println!("    state is {}; done!", n.as_str());
                return Ok(());
            }
            InstanceStateName::Running => true,
            _ => false,
        };

        if (force || shouldstop) && !stopped {
            println!("    {}stopping...", pfx);
            let res = s
                .ec2()
                .stop_instances()
                .instance_ids(id)
                .force(force)
                .send()
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
    s.ec2()
        .modify_instance_attribute()
        .instance_id(id)
        .source_dest_check(
            AttributeBooleanValue::builder().value(!spoof).build(),
        )
        .send()
        .await?;

    Ok(())
}

pub async fn change_instance_type(
    s: &Stuff,
    id: &str,
    new: &str,
    ena: bool,
) -> Result<()> {
    if ena {
        println!("enabling ENA for instance {id}...");
        s.ec2()
            .modify_instance_attribute()
            .instance_id(id)
            .ena_support(AttributeBooleanValue::builder().value(true).build())
            .send()
            .await?;
    }

    println!("setting instance type to {new:?} on instance {id}...");

    s.ec2()
        .modify_instance_attribute()
        .instance_id(id)
        .instance_type(AttributeValueBuilder::default().value(new).build())
        .send()
        .await?;

    Ok(())
}

pub async fn protect_instance(s: &Stuff, id: &str, prot: bool) -> Result<()> {
    println!("setting protect to {} on instance {}...", prot, id);

    s.ec2()
        .modify_instance_attribute()
        .instance_id(id)
        .disable_api_termination(
            AttributeBooleanValue::builder().value(prot).build(),
        )
        .send()
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
                .terminate_instances()
                .instance_ids(id)
                .send()
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
    let mut req = s.ec2().describe_instances();

    match &lookup {
        InstanceLookup::ById(id) => {
            req = req.filters(
                Filter::builder().name("instance-id").values(id).build(),
            )
        }
        InstanceLookup::ByName(name) => {
            req = req.filters(
                Filter::builder().name("tag:Name").values(name).build(),
            )
        }
    };

    let res = req.send().await?;

    let mut out: Vec<Instance> = Vec::new();

    for res in res.reservations() {
        for inst in res.instances() {
            if ignoreterm {
                let stn = inst.state.as_ref().map(|s| s.name()).flatten();
                if matches!(stn, Some(InstanceStateName::Terminated)) {
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
                        .map(|s| s.name())
                        .flatten()
                        .unwrap()
                        .to_owned(),
                    launch: inst
                        .launch_time
                        .map(|dt| {
                            /*
                             * XXX
                             */
                            dt.fmt(DateTimeFormat::DateTime).unwrap()
                        })
                        .unwrap(),
                    tags: inst
                        .tags
                        .as_ref()
                        .map(|o| o.to_vec())
                        .unwrap_or_default(),
                    az: inst.placement.as_ref().map(|p| {
                        p.availability_zone.as_ref().unwrap().to_string()
                    }),
                    raw: inst.clone(),
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
) -> Result<aws_sdk_ec2::types::Volume> {
    let res = s
        .ec2()
        .describe_volumes()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name(if lookuparg.starts_with("vol-") {
                    "volume-id"
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

pub async fn get_image_fuzzy(
    s: &Stuff,
    lookuparg: &str,
) -> Result<aws_sdk_ec2::types::Image> {
    let res = s
        .ec2()
        .describe_images()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name(if lookuparg.starts_with("ami-") {
                    "image-id"
                } else {
                    "name"
                })
                .values(lookuparg)
                .build(),
        )
        .send()
        .await?;

    one_ping_only("image", lookuparg, res.images)
}

pub async fn get_subnet_fuzzy(
    s: &Stuff,
    lookuparg: &str,
) -> Result<aws_sdk_ec2::types::Subnet> {
    let res = s
        .ec2()
        .describe_subnets()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name(if lookuparg.starts_with("subnet-") {
                    "subnet-id"
                } else {
                    "tag:Name"
                })
                .values(lookuparg)
                .build(),
        )
        .send()
        .await?;

    one_ping_only("subnet", lookuparg, res.subnets)
}

pub async fn get_ip_fuzzy(
    s: &Stuff,
    lookuparg: &str,
) -> Result<aws_sdk_ec2::types::Address> {
    let res = s
        .ec2()
        .describe_addresses()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name(if lookuparg.starts_with("eipalloc-") {
                    "allocation-id"
                } else {
                    "tag:Name"
                })
                .values(lookuparg)
                .build(),
        )
        .send()
        .await?;

    one_ping_only("elastic IP", lookuparg, res.addresses)
}

pub async fn get_nat_fuzzy(
    s: &Stuff,
    lookuparg: &str,
) -> Result<aws_sdk_ec2::types::NatGateway> {
    let res = s
        .ec2()
        .describe_nat_gateways()
        .filter(
            aws_sdk_ec2::types::Filter::builder()
                .name(if lookuparg.starts_with("igw-") {
                    "nat-gateway-id"
                } else {
                    "tag:Name"
                })
                .values(lookuparg)
                .build(),
        )
        .send()
        .await?;

    one_ping_only("NAT gateway", lookuparg, res.nat_gateways)
}

pub async fn get_igw_fuzzy(
    s: &Stuff,
    lookuparg: &str,
) -> Result<aws_sdk_ec2::types::InternetGateway> {
    let res = s
        .ec2()
        .describe_internet_gateways()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name(if lookuparg.starts_with("igw-") {
                    "internet-gateway-id"
                } else {
                    "tag:Name"
                })
                .values(lookuparg)
                .build(),
        )
        .send()
        .await?;

    one_ping_only("Internet gateway", lookuparg, res.internet_gateways)
}

pub async fn get_vpc_fuzzy(
    s: &Stuff,
    lookuparg: &str,
) -> Result<aws_sdk_ec2::types::Vpc> {
    let res = s
        .ec2()
        .describe_vpcs()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name(if lookuparg.starts_with("vpc-") {
                    "vpc-id"
                } else {
                    "tag:Name"
                })
                .values(lookuparg)
                .build(),
        )
        .send()
        .await?;

    one_ping_only("VPC", lookuparg, res.vpcs)
}

pub async fn get_sg_fuzzy(s: &Stuff, lookuparg: &str) -> Result<SecurityGroup> {
    let res = s
        .ec2()
        .describe_security_groups()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name(if lookuparg.starts_with("sg-") {
                    "group-id"
                } else {
                    "group-name"
                })
                .values(lookuparg)
                .build(),
        )
        .send()
        .await?;

    one_ping_only("security group", lookuparg, res.security_groups)
}

pub async fn get_rt_fuzzy(
    s: &Stuff,
    lookuparg: &str,
    direct_only: bool,
) -> Result<aws_sdk_ec2::types::RouteTable> {
    let filters = Some(if lookuparg.starts_with("rtb-") {
        vec![aws_sdk_ec2::types::Filter::builder()
            .name("route-table-id")
            .values(lookuparg)
            .build()]
    } else if !direct_only && lookuparg.starts_with("vpc-") {
        /*
         * Get the default route table for this VPC.
         */
        vec![
            aws_sdk_ec2::types::Filter::builder()
                .name("vpc-id")
                .values(lookuparg)
                .build(),
            aws_sdk_ec2::types::Filter::builder()
                .name("association.main")
                .values("true")
                .build(),
        ]
    } else if !direct_only && lookuparg.starts_with("subnet-") {
        /*
         * Get the route table associated with this subnet, if there is one.  If
         * there is not, the default route table for the VPC applies, but for
         * now we are not looking for that here.
         */
        vec![aws_sdk_ec2::types::Filter::builder()
            .name("association.subnet-id")
            .values(lookuparg)
            .build()]
    } else {
        vec![aws_sdk_ec2::types::Filter::builder()
            .name("tag:Name")
            .values(lookuparg)
            .build()]
    });

    let res = s
        .ec2()
        .describe_route_tables()
        .set_filters(filters)
        .send()
        .await?;

    one_ping_only("route table", lookuparg, res.route_tables)
}

pub async fn filter_vpc_fuzzy(
    s: &Stuff,
    optarg: Option<String>,
) -> Result<Option<Vec<aws_sdk_ec2::types::Filter>>> {
    if let Some(optarg) = optarg.as_deref() {
        let vpc = get_vpc_fuzzy(s, optarg).await?;
        Ok(Some(vec![aws_sdk_ec2::types::Filter::builder()
            .name("vpc-id")
            .values(vpc.vpc_id.unwrap())
            .build()]))
    } else {
        Ok(None)
    }
}

/**
 * Use the EBS direct access API to upload a local raw disk image file as a new
 * EBS snapshot.  Returns the snapshot ID.
 */
pub async fn i_upload_snapshot(
    s: &Stuff,
    name: &str,
    file: &str,
) -> Result<String> {
    let mut f = File::open(file)?;

    /*
     * Determine the size of the input file.  We need to round this up to the
     * next whole number of gigabytes for EBS.
     */
    let byte_sz = f.metadata()?.len();
    let gb_sz = (byte_sz + (1 << 30) - 1) / (1 << 30);

    let res = s
        .ebs()
        .start_snapshot()
        .volume_size(gb_sz.try_into().unwrap())
        .tags(
            aws_sdk_ebs::types::Tag::builder()
                .key("Name")
                .value(name)
                .build(),
        )
        .set_timeout(Some(10))
        .send()
        .await?;

    let id = if let Some(id) = res.snapshot_id() {
        println!("snapshot id: {}", id);
        id.to_string()
    } else {
        bail!("no snapshot ID?");
    };

    const CHUNKSZ: u64 = 512 * 1024;

    #[derive(Debug)]
    struct UploadBlock {
        block_index: u64,
        block_data: Vec<u8>,
        sha256: String,
    }

    let mut handles = Vec::new();
    let (tx, rx) = tokio::sync::mpsc::channel::<UploadBlock>(64);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let nblocks = Arc::new(tokio::sync::Mutex::new(0));

    /*
     * Create worker tasks.
     */
    for _ in 0..20 {
        let ebs = s.ebs().clone();
        let rx = Arc::clone(&rx);
        let id = id.clone();
        handles.push(tokio::spawn(async move {
            loop {
                /*
                 * Make sure we do not hold the queue lock while we work on the
                 * item we received.
                 */
                let ub = rx.lock().await.recv().await;

                if let Some(ub) = ub {
                    /*
                     * Upload the chunk!
                     */
                    ebs
                        .put_snapshot_block()
                        .snapshot_id(&id)
                        .block_index(ub.block_index.try_into().unwrap())
                        .block_data(ub.block_data.into())
                        .data_length(CHUNKSZ.try_into().unwrap())
                        .checksum_algorithm(
                            aws_sdk_ebs::types::ChecksumAlgorithm::
                            ChecksumAlgorithmSha256,
                        )
                        .checksum(ub.sha256)
                        .send()
                        .await?;
                } else {
                    /*
                     * When the file reader task is done it will drop the queue,
                     * which tells us there are no more chunks to upload.
                     */
                    return Ok(());
                }
            }
        }));
    }

    /*
     * Create file reader task:
     */
    let nblocks0 = Arc::clone(&nblocks);
    handles.push(tokio::spawn(async move {
        let expected_blocks = byte_sz / CHUNKSZ;
        loop {
            let mut nblocks = nblocks0.lock().await;

            /*
             * EBS apparently operates in chunks of exactly 512KB, at least
             * through this API.
             */
            let mut buf = vec![0u8; CHUNKSZ.try_into().unwrap()];

            let mut off = 0usize;
            let mut eof = false;
            loop {
                let rem = buf.len().checked_sub(off).unwrap();
                if rem == 0 {
                    break;
                }

                match f.read(&mut buf[off..off + rem]) {
                    Ok(0) => {
                        /*
                         * We have reached the end of the file.
                         */
                        if off == 0 {
                            /*
                             * We didn't end up using this buffer, so we do not
                             * need to upload or count it.
                             */
                            return Ok(());
                        }

                        /*
                         * We read a partial chunk, so we need to extend the
                         * buffer out with zeroes so that it is a multiple of
                         * the chunk size.
                         */
                        buf[off..off + rem].fill(0);
                        eof = true;
                        break;
                    }
                    Ok(sz) => {
                        off = off.checked_add(sz).unwrap();
                    }
                    Err(e) => {
                        bail!("reading from file: {:?}", e);
                    }
                }
            }

            {
                let mut out = std::io::stdout();
                write!(
                    out,
                    "\ruploading block {:>7} of {:>7}  {:>3}%    ",
                    (*nblocks) + 1,
                    expected_blocks,
                    100 * (*nblocks) / expected_blocks,
                )?;
                out.flush()?;
            }

            /*
             * Calculate the SHA256 checksum for this chunk.
             */
            let mut digest = sha2::Sha256::new();
            digest.update(&buf);
            let sum = base64_encode(&digest.finalize());

            /*
             * Submit the chunk to the upload work queue:
             */
            tx.send(UploadBlock {
                block_index: *nblocks,
                block_data: buf,
                sha256: sum,
            })
            .await
            .unwrap();

            *nblocks += 1;

            if eof {
                return Ok(());
            }
        }
    }));

    /*
     * Wait for all of the upload tasks and the file reader task to complete.
     * If there is a failure, report it and bail.
     */
    let results = futures::future::join_all(handles).await;
    let mut ok = true;
    for r in results {
        if let Err(e) = r {
            ok = false;
            eprintln!("task failure? {:?}", e);
        }
    }
    if !ok {
        bail!("some tasks failed; aborting");
    }

    println!();

    /*
     * Finalise the snapshot.
     */
    let nblocks = *nblocks.lock().await;
    println!("changed block count = {}", nblocks);
    let res = s
        .ebs()
        .complete_snapshot()
        .snapshot_id(&id)
        .changed_blocks_count(nblocks.try_into().unwrap())
        .send()
        .await?;
    println!("complete = {:#?}", res);

    /*
     * Wait for a terminal state.
     */
    println!("waiting for snapshot to be ready...");
    loop {
        let res = s
            .ec2()
            .describe_snapshots()
            .snapshot_ids(&id)
            .send()
            .await?;

        if let Some(snap) = res.snapshots().first() {
            use aws_sdk_ec2::types::SnapshotState as St;

            match snap.state() {
                Some(St::Completed) => return Ok(id),
                Some(St::Error) => bail!("snapshot now in error state"),
                Some(St::Pending) | None => (),
                x => eprintln!("WARNING: weird snapshot state? {:?}", x),
            }

            sleep(1000);
            continue;
        }

        bail!("could not find snapshot");
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
        .describe_snapshots()
        .snapshot_ids(snapid)
        .send()
        .await?;
    let snap = res.snapshots.unwrap().get(0).unwrap().clone();

    let res = s
        .ec2()
        .register_image()
        .name(name)
        .root_device_name("/dev/sda1")
        .virtualization_type("hvm")
        .architecture(ArchitectureValues::X8664)
        .ena_support(ena)
        .block_device_mappings(
            BlockDeviceMapping::builder()
                .device_name("/dev/sda1")
                .ebs(
                    EbsBlockDevice::builder()
                        .snapshot_id(snapid)
                        .volume_type(VolumeType::Gp2) /* XXX? */
                        .volume_size(snap.volume_size().unwrap())
                        .build(),
                )
                .build(),
        )
        .block_device_mappings(
            BlockDeviceMapping::builder()
                .device_name("/dev/sdb") /* XXX? */
                .virtual_name("ephemeral0") /* XXX? */
                .build(),
        )
        .block_device_mappings(
            BlockDeviceMapping::builder()
                .device_name("/dev/sdc") /* XXX? */
                .virtual_name("ephemeral1") /* XXX? */
                .build(),
        )
        .block_device_mappings(
            BlockDeviceMapping::builder()
                .device_name("/dev/sdd") /* XXX? */
                .virtual_name("ephemeral2") /* XXX? */
                .build(),
        )
        .block_device_mappings(
            BlockDeviceMapping::builder()
                .device_name("/dev/sde") /* XXX? */
                .virtual_name("ephemeral3") /* XXX? */
                .build(),
        )
        .send()
        .await?;

    println!("res: {:#?}", res);

    let imageid = res.image_id.unwrap();
    println!("IMAGE ID: {}", snapid);

    loop {
        let res = s.ec2().describe_images().image_ids(&imageid).send().await?;

        let images = res.images.as_ref().unwrap();

        if images.len() != 1 {
            println!("got {} images?!", images.len());
            sleep(5_000);
            continue;
        }
        let image = &images[0];

        println!("image state: {:#?}", image);

        if image.state.as_ref().map(|s| s.as_str()) == Some("available") {
            return Ok(imageid);
        }

        sleep(5_000);
    }
}

pub async fn i_volume_rm(s: &Stuff, volid: &str, dry_run: bool) -> Result<()> {
    s.ec2()
        .delete_volume()
        .dry_run(dry_run)
        .volume_id(volid)
        .send()
        .await?;

    Ok(())
}

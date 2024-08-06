use crate::prelude::*;

pub async fn do_volume(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list volumes", cmd!(volumes))?; /* XXX */
    l.cmda("destroy", "rm", "destroy a volume", cmd!(do_volume_rm))?;
    l.cmd("create", "create a volume", cmd!(do_volume_create))?;
    l.cmd("attach", "attach a volume", cmd!(do_volume_attach))?;
    l.cmd("detach", "detach a volume", cmd!(do_volume_detach))?;
    l.cmd(
        "snapshot",
        "create a snapshot of a volume",
        cmd!(do_volume_snapshot),
    )?;
    l.cmd(
        "resize",
        "adjust the size of a volume",
        cmd!(do_volume_resize),
    )?;

    sel!(l).run().await
}

async fn volumes(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("creation", WIDTH_UTC, false);
    l.add_column("id", 21, true);
    l.add_column("state", 10, true);
    l.add_column("natt", 4, true); /* Number of attachments */
    l.add_column("size", 8, true);
    l.add_column("info", 30, true);
    l.add_column("snapshot", 22, false);
    l.add_column("name", 24, false);
    l.add_column("az", WIDTH_AZ, false);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s.ec2().describe_volumes().send().await?;

    for v in res.volumes() {
        let mut r = Row::default();

        /*
         * The magic INFO column contains information we were able to glean by
         * looking further afield.
         */
        let atts = v.attachments();
        let info = if atts.len() != 1 {
            v.tags.tag("Name").as_deref().unwrap_or("-").to_string()
        } else {
            let a = atts.iter().next().unwrap();

            if let Some(aid) = a.instance_id() {
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

        r.add_stror("id", v.volume_id.as_deref(), "?");
        r.add_str("info", &info);
        r.add_stror("state", v.state().map(|v| v.as_str()), "-");
        r.add_bytes("size", (v.size.unwrap_or(0) as u64) * 1024 * 1024 * 1024);
        r.add_stror("snapshot", v.snapshot_id.as_deref(), "-");
        r.add_stror("name", v.tags.tag("Name").as_deref(), "-");
        r.add_stror("creation", v.create_time.as_utc().as_deref(), "-");
        r.add_stror("az", v.availability_zone.as_deref(), "-");
        r.add_u64("natt", atts.len() as u64);

        t.add_row(r);
    }

    print!("{}", t.output()?);

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

async fn do_volume_create(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME SIZE_GB"));

    l.reqopt("A", "az", "availability zone for subnet creation", "AZ");
    l.optopt("t", "type", "volume type", "TYPE");

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify volume name and size in gigabytes");
    }

    let size: i32 = a.args().get(1).unwrap().parse()?;

    let tags = aws_sdk_ec2::types::TagSpecification::builder()
        .resource_type(aws_sdk_ec2::types::ResourceType::Volume)
        .tags(
            aws_sdk_ec2::types::Tag::builder()
                .key("Name")
                .value(a.args().get(0).unwrap())
                .build(),
        )
        .build();

    let res = s
        .ec2()
        .create_volume()
        .tag_specifications(tags)
        .size(size)
        .set_availability_zone(a.opts().opt_str("az"))
        .set_volume_type(a.opts().opt_str("type").map(|t| t.as_str().into()))
        .send()
        .await?;

    println!("{:#?}", res);
    Ok(())
}

async fn do_volume_detach(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("INSTANCE VOLUME DEVPATH"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 3 {
        bad_args!(l, "specify instance, volume, and device name");
    }

    let i = get_instance_fuzzy(s, a.args().get(0).unwrap().as_str()).await?;
    let v = get_vol_fuzzy(s, a.args().get(1).unwrap().as_str()).await?;

    let res = s
        .ec2()
        .detach_volume()
        .instance_id(&i.id)
        .volume_id(v.volume_id().unwrap())
        .device(a.args().get(2).unwrap())
        .send()
        .await?;

    println!("{:#?}", res);
    Ok(())
}

async fn do_volume_attach(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("INSTANCE VOLUME DEVPATH"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 3 {
        bad_args!(l, "specify instance, volume, and device name");
    }

    let i = get_instance_fuzzy(s, a.args().get(0).unwrap().as_str()).await?;
    let v = get_vol_fuzzy(s, a.args().get(1).unwrap().as_str()).await?;

    let res = s
        .ec2()
        .attach_volume()
        .instance_id(&i.id)
        .volume_id(v.volume_id().unwrap())
        .device(a.args().get(2).unwrap())
        .send()
        .await?;

    println!("{:#?}", res);
    Ok(())
}

async fn do_volume_snapshot(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("VOLUME SNAPSHOT-NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify volume and snapshot name");
    }

    let v = get_vol_fuzzy(s, a.args().get(0).unwrap().as_str()).await?;

    let tags = aws_sdk_ec2::types::TagSpecification::builder()
        .resource_type(aws_sdk_ec2::types::ResourceType::Snapshot)
        .tags(
            aws_sdk_ec2::types::Tag::builder()
                .key("Name")
                .value(a.args().get(1).unwrap())
                .build(),
        )
        .build();

    let res = s
        .ec2()
        .create_snapshot()
        .volume_id(v.volume_id.as_deref().unwrap())
        .tag_specifications(tags)
        .send()
        .await?;

    println!("{:#?}", res);

    if let Some(id) = &res.snapshot_id {
        println!("snapshot id = {id}");
    }

    Ok(())
}

async fn do_volume_resize(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("VOLUME SIZE_GB"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify volume and new size in gigabytes");
    }

    let newsize: i32 = a.args().get(1).unwrap().parse()?;
    let v = get_vol_fuzzy(s, a.args().get(0).unwrap().as_str()).await?;

    if let Some(oldsize) = v.size() {
        if oldsize == newsize {
            eprintln!(
                "volume size is already {oldsize}GiB, no action required"
            );
            return Ok(());
        } else if oldsize > newsize {
            bail!("volume is already {oldsize}GiB; volumes can only grow");
        }
    } else {
        bail!("could not determine existing volume size");
    }

    let res = s
        .ec2()
        .modify_volume()
        .volume_id(v.volume_id.as_deref().unwrap())
        .size(newsize)
        .send()
        .await?;

    println!("{:#?}", res);

    Ok(())
}

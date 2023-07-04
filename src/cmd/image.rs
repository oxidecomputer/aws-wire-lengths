use crate::prelude::*;

pub async fn do_image(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list images", cmd!(images))?; /* XXX */
    l.cmd("dump", "dump information about an image", cmd!(image_dump))?;
    l.cmda("destroy", "rm", "destroy an image", cmd!(do_image_rm))?;
    l.cmd(
        "publish",
        "publish a raw file as an AMI",
        cmd!(ami_from_file),
    )?;
    l.cmd("register", "register a snapshot as an AMI", cmd!(register))?;
    l.cmd("copy", "copy an AMI to another region", cmd!(do_image_copy))?;
    l.cmd(
        "grant",
        "add launch permission for an account",
        cmd!(image_grant),
    )?;
    l.cmd(
        "revoke",
        "remove launch permission from an account",
        cmd!(image_revoke),
    )?;

    sel!(l).run().await
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
            .deregister_image(ec2::DeregisterImageRequest {
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

async fn image_grant(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("AMI-ID|NAME ACCOUNT"));

    let a = args!(l);
    let c = l.context().more().ec2();

    if a.args().len() != 2 {
        bad_args!(l, "specify image ID or name, and the account to allow");
    }

    let image = get_image_fuzzy(l.context(), a.args()[0].as_str()).await?;
    eprintln!("image = {}", image.image_id().unwrap());

    let res = c
        .modify_image_attribute()
        .image_id(image.image_id().unwrap())
        .attribute("launchPermission")
        .launch_permission(
            aws_sdk_ec2::types::LaunchPermissionModifications::builder()
                .add(
                    aws_sdk_ec2::types::LaunchPermission::builder()
                        .user_id(a.args().get(1).unwrap().as_str())
                        .build(),
                )
                .build(),
        )
        .send()
        .await?;

    println!("{:#?}", res);
    Ok(())
}

async fn image_revoke(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("AMI-ID|NAME ACCOUNT"));

    let a = args!(l);
    let c = l.context().more().ec2();

    if a.args().len() != 2 {
        bad_args!(l, "specify image ID or name, and the account to disallow");
    }

    let image = get_image_fuzzy(l.context(), a.args()[0].as_str()).await?;
    eprintln!("image = {}", image.image_id().unwrap());

    let res = c
        .modify_image_attribute()
        .image_id(image.image_id().unwrap())
        .attribute("launchPermission")
        .launch_permission(
            aws_sdk_ec2::types::LaunchPermissionModifications::builder()
                .remove(
                    aws_sdk_ec2::types::LaunchPermission::builder()
                        .user_id(a.args().get(1).unwrap().as_str())
                        .build(),
                )
                .build(),
        )
        .send()
        .await?;

    println!("{:#?}", res);
    Ok(())
}

async fn do_image_copy(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("AMI-ID|NAME TARGET_REGION"));
    l.optflag("W", "no-wait", "do not wait for copy to complete");

    let a = args!(l);

    let wait = !a.opts().opt_present("no-wait");

    if a.args().len() != 2 {
        bad_args!(l, "specify image ID or name, and the destination region");
    }

    let image = get_image_fuzzy(l.context(), a.args()[0].as_str()).await?;
    eprintln!("image = {}", image.image_id().unwrap());

    let target = l
        .context()
        .more()
        .ec2_for_region(a.args()[1].as_str())
        .await;
    let res = target
        .copy_image()
        .name(image.name().unwrap())
        .source_image_id(image.image_id().unwrap())
        .source_region(l.context().more().region_ec2().to_string())
        .send()
        .await?;

    let new_image = res.image_id().unwrap();

    if wait {
        /*
         * Wait for the image to leave the pending state in the target region.
         */
        eprintln!("new image = {}", new_image);
        eprintln!("waiting for image to be available...");
        loop {
            let image = match target
                .describe_images()
                .image_ids(new_image)
                .send()
                .await
            {
                Ok(res) => {
                    if let Some(mut images) = res.images {
                        if images.len() != 1 {
                            bail!(
                                "could not find image {} on target region",
                                new_image
                            );
                        }
                        images.pop().unwrap()
                    } else {
                        eprintln!("ERROR: images missing from response");
                        sleep(1000);
                        continue;
                    }
                }
                Err(e) => {
                    eprintln!("ERROR: {:?}", e);
                    sleep(1000);
                    continue;
                }
            };

            match image.state {
                Some(aws_sdk_ec2::types::ImageState::Available) => {
                    eprintln!(
                        "image is now available in {}",
                        a.args()[1].as_str()
                    );
                    break;
                }
                Some(aws_sdk_ec2::types::ImageState::Pending) | None => {}
                Some(other) => {
                    bail!("unexpected image state = {:?}", other);
                }
            }

            sleep(5000);
            continue;
        }
    }

    println!("{}", new_image);
    Ok(())
}

async fn image_dump(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("AMI-ID|NAME"));

    let a = args!(l);
    let c = l.context().more().ec2();

    if a.args().len() != 1 {
        bad_args!(l, "specify image ID or name");
    }

    let image = get_image_fuzzy(l.context(), a.args()[0].as_str()).await?;
    println!("image = {:#?}", image);

    let res = c
        .describe_image_attribute()
        .attribute(aws_sdk_ec2::types::ImageAttributeName::LaunchPermission)
        .image_id(image.image_id().unwrap())
        .send()
        .await?;
    println!(
        "launch permission = {:#?}",
        res.launch_permissions.unwrap_or_default()
    );

    Ok(())
}

async fn images(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", 21, true);
    l.add_column("name", 32, true);
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

pub async fn register(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME SNAP-ID"));
    l.optflag("E", "ena", "enable ENA support");

    let a = args!(l);

    if a.args().len() != 2 {
        bad_args!(l, "specify image name and snapshot ID");
    }

    let name = a.args().get(0).cloned().unwrap();
    let snap = a.args().get(1).cloned().unwrap();

    i_register_image(l.context(), &name, &snap, a.opts().opt_present("E"))
        .await?;

    Ok(())
}

pub async fn ami_from_file(mut l: Level<Stuff>) -> Result<()> {
    /*
     * Ignore these options silently for now.  They were necessary when we were
     * using the old ImportVolume API, where the data must first be uploaded to
     * S3.  Now that we use the EBS direct API, an S3 bucket is no longer
     * required.
     */
    l.optopt("b", "bucket", "S3 bucket (ignored)", "BUCKET");
    l.optopt("p", "prefix", "S3 prefix (ignored)", "PREFIX");

    l.reqopt("n", "name", "target image name", "NAME");
    l.optflag("E", "ena", "enable ENA support");
    l.reqopt("f", "file", "local file to upload", "FILENAME");

    let a = no_args!(l);

    let name = a.opts().opt_str("n").unwrap();
    let file = a.opts().opt_str("f").unwrap();
    let support_ena = a.opts().opt_present("E");

    println!("UPLOADING SNAPSHOT:");
    let snapid = i_upload_snapshot(l.context(), &name, &file).await?;
    println!("COMPLETED SNAPSHOT ID: {}", snapid);

    println!("REGISTERING IMAGE:");
    let ami =
        i_register_image(l.context(), &name, &snapid, support_ena).await?;
    println!("COMPLETED IMAGE ID: {}", ami);

    Ok(())
}

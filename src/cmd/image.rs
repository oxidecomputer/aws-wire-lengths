use crate::prelude::*;

pub async fn do_image(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list images", cmd!(images))?; /* XXX */
    l.cmda("destroy", "rm", "destroy an image", cmd!(do_image_rm))?;
    l.cmd(
        "publish",
        "publish a raw file as an AMI",
        cmd!(ami_from_file),
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

pub async fn ami_from_file(mut l: Level<Stuff>) -> Result<()> {
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


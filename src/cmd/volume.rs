use crate::prelude::*;

pub async fn do_volume(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list volumes", cmd!(volumes))?; /* XXX */
    l.cmda("destroy", "rm", "destroy a volume", cmd!(do_volume_rm))?;

    sel!(l).run().await
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
    l.add_column("az", WIDTH_AZ, false);

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

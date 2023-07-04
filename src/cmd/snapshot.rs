use crate::prelude::*;

pub async fn do_snapshot(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list snapshots", cmd!(snapshots))?; /* XXX */
    l.cmda("destroy", "rm", "destroy a snapshot", cmd!(do_snapshot_rm))?;
    l.cmd("upload", "upload a snapshot", cmd!(do_snapshot_upload))?;

    sel!(l).run().await
}

async fn do_snapshot_upload(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME FILE"));

    let a = args!(l);

    if a.args().len() != 2 {
        bad_args!(l, "specify snapshot name and local file path");
    }

    let name = a.args().get(0).cloned().unwrap();
    let file = a.args().get(1).cloned().unwrap();

    i_upload_snapshot(l.context(), &name, &file).await?;

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
            .delete_snapshot()
            .dry_run(dry_run)
            .snapshot_id(id)
            .send()
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
    l.add_column("start", WIDTH_UTC, true);
    l.add_column("size", 5, true);
    l.add_column("state", 10, true);
    l.add_column("desc", 30, true);
    l.add_column("volume", 22, false);
    l.add_column("name", 32, false);
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
        .describe_snapshots()
        .owner_ids("self")
        .set_snapshot_ids(snapshot_ids)
        .send()
        .await?;

    let x = Vec::new();
    for s in res.snapshots.as_ref().unwrap_or(&x) {
        let mut r = Row::default();

        r.add_stror("id", &s.snapshot_id, "?");
        r.add_stror("start", &s.start_time.as_utc(), "-");
        r.add_stror(
            "state",
            &s.state.as_ref().map(|s| s.as_str().to_string()),
            "-",
        );
        r.add_u64("size", s.volume_size.unwrap_or(0) as u64);
        r.add_stror("volume", &s.volume_id, "-");
        r.add_stror("desc", &s.description, "-");
        r.add_stror("name", &s.tags.tag("Name"), "-");

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

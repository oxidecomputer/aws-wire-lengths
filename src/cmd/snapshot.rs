use crate::prelude::*;

pub async fn do_snapshot(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list snapshots", cmd!(snapshots))?; /* XXX */
    l.cmda("destroy", "rm", "destroy a snapshot", cmd!(do_snapshot_rm))?;

    sel!(l).run().await
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
            .delete_snapshot(ec2::DeleteSnapshotRequest {
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

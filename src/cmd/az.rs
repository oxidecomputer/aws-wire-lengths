use crate::prelude::*;

use aws_sdk_ec2::types::AvailabilityZoneState;

pub async fn do_az(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list availability zones", cmd!(do_az_ls))?;

    sel!(l).run().await
}

pub async fn do_az_ls(mut l: Level<Stuff>) -> Result<()> {
    l.optflag("a", "all", "all zones, including those not opted in");

    l.add_column("name", 23, true);
    l.add_column("type", 10, true);
    l.add_column("state", 11, true);
    l.add_column("group", 23, false);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s
        .ec2()
        .describe_availability_zones()
        .all_availability_zones(a.opts().opt_present("all"))
        .send()
        .await?;

    for az in res.availability_zones() {
        let mut r = Row::default();

        r.add_stror("name", az.zone_name.as_deref(), "?");
        r.add_str(
            "type",
            match &az.zone_type.as_deref() {
                Some("availability-zone") => "az",
                Some("local-zone") => "local",
                Some("wavelength-zone") => "wavelength",
                Some(x) => x,
                None => "-",
            },
        );

        let state = az.state.as_ref().map(|st| {
            match st {
                AvailabilityZoneState::Available => "available",
                AvailabilityZoneState::Impaired => "impaired",
                AvailabilityZoneState::Information => "information",
                AvailabilityZoneState::Unavailable => "unavailable",
                _ => "unknown",
            }
            .to_string()
        });
        r.add_stror("state", state.as_deref(), "-");
        r.add_stror("group", az.network_border_group.as_deref(), "-");

        t.add_row(r);
    }

    print!("{}", t.output()?);
    Ok(())
}

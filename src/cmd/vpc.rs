use crate::prelude::*;

pub async fn do_vpc(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list VPCs", cmd!(do_vpc_ls))?;
    l.cmd("id", "lookup VPC ID", cmd!(do_vpc_id))?;
    l.cmd("peering", "manage peering connections", cmd!(do_peering))?;

    sel!(l).run().await
}

async fn do_peering(mut l: Level<Stuff>) -> Result<()> {
    l.cmda(
        "list",
        "ls",
        "list peering connections",
        cmd!(do_peering_ls),
    )?;
    l.cmda(
        "delete",
        "rm",
        "remove a peering connection",
        cmd!(do_peering_rm),
    )?;

    sel!(l).run().await
}

async fn do_peering_rm(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("PCX-ID|NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify peering connection");
    }

    s.ec2()
        .delete_vpc_peering_connection(ec2::DeleteVpcPeeringConnectionRequest {
            vpc_peering_connection_id: a.args().get(0).unwrap().to_string(),
            ..Default::default()
        })
        .await?;

    Ok(())
}

async fn do_peering_ls(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", WIDTH_PCX, true);
    l.add_column("requester", WIDTH_VPC, true);
    l.add_column("accepter", WIDTH_VPC, true);
    l.add_column("status", 10, true);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s
        .ec2()
        .describe_vpc_peering_connections(
            ec2::DescribeVpcPeeringConnectionsRequest {
                ..Default::default()
            },
        )
        .await?;

    for pc in res.vpc_peering_connections.unwrap_or_default() {
        let mut r = Row::default();

        r.add_stror("id", &pc.vpc_peering_connection_id, "?");
        r.add_stror(
            "accepter",
            &pc.accepter_vpc_info.as_ref().unwrap().vpc_id,
            "-",
        );
        r.add_stror(
            "requester",
            &pc.requester_vpc_info.as_ref().unwrap().vpc_id,
            "-",
        );
        r.add_stror("status", &pc.status.unwrap().code, "-");

        t.add_row(r);
    }

    print!("{}", t.output()?);
    Ok(())
}

async fn do_vpc_ls(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", WIDTH_VPC, true);
    l.add_column("name", 20, true);
    l.add_column("cidr", 18, true);
    l.add_column("flags", 5, true);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s.more().ec2().describe_vpcs().send().await?;

    let empty = Vec::new();
    for vpc in res.vpcs.as_ref().unwrap_or(&empty) {
        let name = vpc.tags.tag("Name");
        let flags = [vpc.is_default.as_flag("D")].join("");

        let mut r = Row::default();

        r.add_stror("id", &vpc.vpc_id, "?");
        r.add_stror("name", &name, "-");
        r.add_stror("cidr", &vpc.cidr_block, "-");
        r.add_str("flags", &flags);

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn do_vpc_id(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify VPC name to look up");
    }

    let vpc = get_vpc_fuzzy(s, a.args().get(0).unwrap()).await?;

    println!("{}", vpc.vpc_id.unwrap());

    Ok(())
}

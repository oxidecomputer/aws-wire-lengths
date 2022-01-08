use crate::prelude::*;

pub async fn do_subnet(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list subnets", cmd!(do_subnet_ls))?;

    sel!(l).run().await
}

async fn do_subnet_ls(mut l: Level<Stuff>) -> Result<()> {
    l.optopt("V", "vpc", "filter instances by VPC name or ID", "VPC");

    l.add_column("id", 24, true);
    l.add_column("name", 20, true);
    l.add_column("cidr", 18, true);
    l.add_column("az", 14, false);
    l.add_column("vpc", WIDTH_VPC, false);
    l.add_column("flags", 5, true);
    l.add_column("avail", 5, true);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let filters = if let Some(vpc) = a.opts().opt_str("vpc") {
        let vpc = get_vpc_fuzzy(s, &vpc).await?;
        Some(vec![ec2::Filter {
            name: Some("vpc-id".to_string()),
            values: Some(vec![vpc.vpc_id.unwrap().to_string()]),
        }])
    } else {
        None
    };

    let res = s
        .ec2()
        .describe_subnets(ec2::DescribeSubnetsRequest {
            filters,
            ..Default::default()
        })
        .await?;

    let x = Vec::new();
    for sn in res.subnets.as_ref().unwrap_or(&x) {
        /*
         * Find the name tag value:
         */
        let nametag = if let Some(tags) = sn.tags.as_ref() {
            tags.iter()
                .find(|t| t.key.as_deref() == Some("Name"))
                .and_then(|t| t.value.as_deref())
                .map(|s| s.to_string())
        } else {
            None
        };

        let flags = [
            sn.map_public_ip_on_launch.as_flag("P"),
            sn.default_for_az.as_flag("D"),
        ]
        .join("");

        let mut r = Row::default();

        r.add_stror("id", &sn.subnet_id, "?");
        r.add_stror("vpc", &sn.vpc_id, "-");
        r.add_stror("cidr", &sn.cidr_block, "-");
        r.add_stror("name", &nametag, "-");
        r.add_stror("az", &sn.availability_zone, "-");
        r.add_str("flags", &flags);
        r.add_u64("avail", sn.available_ip_address_count.unwrap_or(0) as u64);

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

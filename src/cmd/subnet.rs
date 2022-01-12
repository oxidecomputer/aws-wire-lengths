use crate::prelude::*;

pub async fn do_subnet(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list subnets", cmd!(do_subnet_ls))?;
    l.cmd("create", "create a subnet", cmd!(create))?;

    sel!(l).run().await
}

async fn create(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME CIDR"));

    l.reqopt("V", "vpc", "VPC name or ID for subnet creation", "VPC");
    l.reqopt("A", "az", "availability zone for subnet creation", "AZ");

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify the name and CIDR block for the subnet");
    }
    let name = a.args().get(0).unwrap().to_string();
    let cidr_block = a.args().get(0).unwrap().to_string();

    let vpc = get_vpc_fuzzy(s, &a.opts().opt_str("vpc").unwrap()).await?;

    let tag_specifications = Some(vec![ec2::TagSpecification {
        resource_type: ss("subnet"),
        tags: Some(vec![ec2::Tag {
            key: ss("Name"),
            value: Some(name),
        }]),
    }]);

    let res = s
        .ec2()
        .create_subnet(ec2::CreateSubnetRequest {
            availability_zone: a.opts().opt_str("az"),
            cidr_block,
            tag_specifications,
            vpc_id: vpc.vpc_id.unwrap(),
            ..Default::default()
        })
        .await?;

    println!("{}", res.subnet.unwrap().subnet_id.unwrap());
    Ok(())
}

async fn do_subnet_ls(mut l: Level<Stuff>) -> Result<()> {
    l.optopt("V", "vpc", "filter instances by VPC name or ID", "VPC");

    l.add_column("id", 24, true);
    l.add_column("name", 20, true);
    l.add_column("cidr", 18, true);
    l.add_column("az", WIDTH_AZ, false);
    l.add_column("vpc", WIDTH_VPC, false);
    l.add_column("flags", 5, true);
    l.add_column("avail", 5, true);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let filters = filter_vpc_fuzzy(s, a.opts().opt_str("vpc")).await?;

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

use crate::prelude::*;

pub async fn do_subnet(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list subnets", cmd!(do_subnet_ls))?;
    l.cmd("create", "create a subnet", cmd!(create))?;
    l.cmd("destroy", "destroy a subnet", cmd!(destroy))?;

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
    let cidr_block = a.args().get(1).unwrap().to_string();

    let vpc = get_vpc_fuzzy(s, &a.opts().opt_str("vpc").unwrap()).await?;

    let res = l
        .context()
        .more()
        .ec2()
        .create_subnet()
        .vpc_id(vpc.vpc_id.unwrap())
        .availability_zone(a.opts().opt_str("az").unwrap())
        .cidr_block(cidr_block)
        .tag_specifications(
            aws_sdk_ec2::model::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::model::ResourceType::Subnet)
                .tags(
                    aws_sdk_ec2::model::Tag::builder()
                        .key("Name")
                        .value(name)
                        .build(),
                )
                .build(),
        )
        .send()
        .await?;

    println!("{}", res.subnet.unwrap().subnet_id.unwrap());
    Ok(())
}

async fn destroy(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("SUBNET-ID|NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the name of the subnet to destroy");
    }

    let subnet = get_subnet_fuzzy(s, a.args().get(0).unwrap().as_str()).await?;

    l.context()
        .more()
        .ec2()
        .delete_subnet()
        .subnet_id(subnet.subnet_id().unwrap())
        .send()
        .await?;

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
        .more()
        .ec2()
        .describe_subnets()
        .set_filters(filters)
        .send()
        .await?;

    let x = Vec::new();
    for sn in res.subnets.as_ref().unwrap_or(&x) {
        let nametag = sn.tags.tag("Name");

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

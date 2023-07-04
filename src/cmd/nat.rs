use crate::prelude::*;

pub async fn do_nat(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list NAT gateways", cmd!(list))?;
    l.cmd("create", "create a NAT gateway", cmd!(create))?;

    sel!(l).run().await
}

async fn list(mut l: Level<Stuff>) -> Result<()> {
    l.optopt("V", "vpc", "filter gateways by VPC name or ID", "VPC");

    l.add_column("id", WIDTH_NAT, true);
    l.add_column("vpc", WIDTH_VPC, true);
    l.add_column("name", 24, true);

    let a = no_args!(l);
    let s = l.context();
    let mut t = a.table();

    let filters = if let Some(la) = a.opts().opt_str("vpc") {
        Some(vec![aws_sdk_ec2::types::Filter::builder()
            .name("vpc-id")
            .values(get_vpc_fuzzy(s, &la).await?.vpc_id.unwrap())
            .build()])
    } else {
        None
    };

    let res = s
        .ec2()
        .describe_nat_gateways()
        .set_filter(filters)
        .send()
        .await?;

    for nat in res.nat_gateways.unwrap_or_default().iter() {
        let n = nat.tags.tag("Name");

        let mut r = Row::default();
        r.add_stror("id", &nat.nat_gateway_id, "?");
        r.add_stror("name", &n, "-");
        r.add_stror("vpc", &nat.vpc_id, "-");
        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn create(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME SUBNET-ID|NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify the name for the NAT gateway, and the subnet");
    }
    let name = a.args().get(0).unwrap().to_string();
    let net = get_subnet_fuzzy(s, a.args().get(1).unwrap().as_str()).await?;

    let nametag = aws_sdk_ec2::types::Tag::builder()
        .key("Name")
        .value(&name)
        .build();

    /*
     * Allocate an Elastic IP for this gateway.
     */
    let res = s
        .ec2()
        .allocate_address()
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::ElasticIp)
                .tags(nametag.clone())
                .build(),
        )
        .send()
        .await?;

    eprintln!(
        "using IP address {} with allocation {}",
        res.public_ip().unwrap(),
        res.allocation_id().unwrap()
    );

    let res = s
        .ec2()
        .create_nat_gateway()
        .subnet_id(net.subnet_id().unwrap())
        .allocation_id(res.allocation_id().unwrap())
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::Natgateway)
                .tags(nametag)
                .build(),
        )
        .send()
        .await?;

    println!("{}", res.nat_gateway().unwrap().nat_gateway_id().unwrap());
    Ok(())
}

use crate::prelude::*;

pub async fn do_gateway(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list Internet gateways", cmd!(list))?;
    l.cmd("create", "create an Internet gateway", cmd!(create))?;
    l.cmd("destroy", "destroy an Internet gateway", cmd!(destroy))?;
    l.cmd("attach", "attach Internet gateway to VPC", cmd!(attach))?;
    l.cmd("detach", "detach Internet gateway from VPC", cmd!(detach))?;

    sel!(l).run().await
}

async fn list(mut l: Level<Stuff>) -> Result<()> {
    l.optopt("V", "vpc", "filter gateways by VPC name or ID", "VPC");

    l.add_column("id", WIDTH_IGW, true);
    l.add_column("vpc", WIDTH_VPC, true);
    l.add_column("name", 24, true);

    let a = no_args!(l);
    let s = l.context();
    let mut t = a.table();

    let filters = if let Some(la) = a.opts().opt_str("vpc") {
        Some(vec![aws_sdk_ec2::model::Filter::builder()
            .name("attachment.vpc-id")
            .values(get_vpc_fuzzy(s, &la).await?.vpc_id.unwrap())
            .build()])
    } else {
        None
    };

    let res = s
        .more()
        .ec2()
        .describe_internet_gateways()
        .set_filters(filters)
        .send()
        .await?;

    for igw in res.internet_gateways.unwrap_or_default().iter() {
        let n = igw.tags.tag("Name");

        let vpc = if let Some(atts) = igw.attachments() {
            match atts.len() {
                0 => None,
                1 => Some(atts[0].vpc_id().unwrap().to_string()),
                n => bail!("expected 0 or 1, not {}, attachments", n),
            }
        } else {
            None
        };

        let mut r = Row::default();
        r.add_stror("id", &igw.internet_gateway_id, "?");
        r.add_stror("name", &n, "-");
        r.add_stror("vpc", &vpc, "-");
        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn create(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the name for the Internet gateway");
    }
    let name = a.args().get(0).unwrap().to_string();

    let res = s
        .more()
        .ec2()
        .create_internet_gateway()
        .tag_specifications(
            aws_sdk_ec2::model::TagSpecification::builder()
                .resource_type(
                    aws_sdk_ec2::model::ResourceType::InternetGateway,
                )
                .tags(
                    aws_sdk_ec2::model::Tag::builder()
                        .key("Name")
                        .value(&name)
                        .build(),
                )
                .build(),
        )
        .send()
        .await?;

    println!(
        "{}",
        res.internet_gateway()
            .unwrap()
            .internet_gateway_id()
            .unwrap()
    );
    Ok(())
}

async fn attach(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("IGW-ID|NAME VPC-ID|NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify the Internet gateway and the VPC");
    }

    let igw = get_igw_fuzzy(s, a.args().get(0).unwrap().as_str()).await?;
    let vpc = get_vpc_fuzzy(s, a.args().get(1).unwrap().as_str()).await?;

    s.more()
        .ec2()
        .attach_internet_gateway()
        .internet_gateway_id(igw.internet_gateway_id().unwrap())
        .vpc_id(vpc.vpc_id.as_deref().unwrap())
        .send()
        .await?;

    Ok(())
}

async fn detach(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("IGW-ID|NAME VPC-ID|NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify the Internet gateway and the VPC");
    }

    let igw = get_igw_fuzzy(s, a.args().get(0).unwrap().as_str()).await?;
    let vpc = get_vpc_fuzzy(s, a.args().get(1).unwrap().as_str()).await?;

    s.more()
        .ec2()
        .detach_internet_gateway()
        .internet_gateway_id(igw.internet_gateway_id().unwrap())
        .vpc_id(vpc.vpc_id.as_deref().unwrap())
        .send()
        .await?;

    Ok(())
}

async fn destroy(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("IGW-ID|NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the name of the Internet gateway to destroy");
    }
    let name = a.args().get(0).unwrap().to_string();

    let igw = get_igw_fuzzy(s, &name).await?;

    s.more()
        .ec2()
        .delete_internet_gateway()
        .internet_gateway_id(igw.internet_gateway_id().unwrap())
        .send()
        .await?;

    Ok(())
}

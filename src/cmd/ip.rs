use crate::prelude::*;

pub async fn do_ip(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list elastic IP addresses", cmd!(list))?;
    l.cmd("create", "create an elastic IP address", cmd!(create))?;
    l.cmd("destroy", "destroy an elastic IP address", cmd!(destroy))?;
    l.cmd(
        "attach",
        "attach an elastic IP to an instance",
        cmd!(attach),
    )?;
    l.cmd(
        "detach",
        "detach an elastic IP from any instances",
        cmd!(detach),
    )?;

    sel!(l).run().await
}

async fn create(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the name for this elastic IP");
    }

    let res = s
        .ec2()
        .allocate_address()
        .domain(aws_sdk_ec2::types::DomainType::Vpc)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::ElasticIp)
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("Name")
                        .value(a.args().get(0).unwrap())
                        .build(),
                )
                .build(),
        )
        .send()
        .await?;

    println!("{}", res.public_ip.unwrap());
    Ok(())
}

async fn destroy(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the name for this elastic IP");
    }

    let eip = get_ip_fuzzy(s, a.args().get(0).as_ref().unwrap()).await?;

    s.ec2()
        .release_address()
        .set_allocation_id(eip.allocation_id)
        .send()
        .await?;

    Ok(())
}

async fn attach(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("EIPALLOC-ID|IP-NAME I-ID|INSTANCE-NAME"));

    l.optflag("f", "", "allow reassociation even if IP already in use");

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify the name/ID of the IP and of the instance");
    }

    let eip = get_ip_fuzzy(s, a.args().get(0).as_ref().unwrap()).await?;
    let inst = get_instance_fuzzy(s, a.args().get(1).as_ref().unwrap()).await?;

    s.ec2()
        .associate_address()
        .set_allocation_id(eip.allocation_id)
        .instance_id(inst.id)
        .allow_reassociation(a.opts().opt_present("f"))
        .send()
        .await?;

    Ok(())
}

async fn detach(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("EIPALLOC-ID|IP-NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the name/ID of the IP");
    }

    let eip = get_ip_fuzzy(s, a.args().get(0).as_ref().unwrap()).await?;

    if let Some(assoc) = eip.association_id() {
        s.ec2()
            .disassociate_address()
            .association_id(assoc)
            .send()
            .await?;
    }

    Ok(())
}

async fn list(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", WIDTH_EIP, true);
    l.add_column("ip", 15, true);
    l.add_column("name", 24, true);

    let a = no_args!(l);
    let s = l.context();
    let mut t = a.table();

    let res = s.ec2().describe_addresses().send().await?;

    for addr in res.addresses() {
        let n = addr.tags.tag("Name");

        let mut r = Row::default();
        r.add_stror("id", addr.allocation_id.as_deref(), "?");
        r.add_stror("name", n.as_deref(), "-");
        r.add_stror("ip", addr.public_ip.as_deref(), "-");
        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

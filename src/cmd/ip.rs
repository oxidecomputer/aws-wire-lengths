use crate::prelude::*;

pub async fn do_ip(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list elastic IP addresses", cmd!(list))?;

    sel!(l).run().await
}

async fn list(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", WIDTH_EIP, true);
    l.add_column("ip", 15, true);
    l.add_column("name", 24, true);

    let a = no_args!(l);
    let s = l.context();
    let mut t = a.table();

    let res = s
        .more()
        .ec2()
        .describe_addresses()
        .send()
        .await?;

    for addr in res.addresses().unwrap_or_default().iter() {
        let n = addr.tags.tag("Name");

        let mut r = Row::default();
        r.add_stror("id", &addr.allocation_id, "?");
        r.add_stror("name", &n, "-");
        r.add_stror("ip", &addr.public_ip, "-");
        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

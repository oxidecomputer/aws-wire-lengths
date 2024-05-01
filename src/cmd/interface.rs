use crate::prelude::*;

pub async fn do_if(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list network interfaces", cmd!(list))?;

    sel!(l).run().await
}

async fn list(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", WIDTH_ENI, true);
    l.add_column("type", 21, true);
    l.add_column("eip", WIDTH_EIP, true);
    l.add_column("name", 24, false);

    let a = no_args!(l);
    let s = l.context();
    let mut t = a.table();

    let res = s.ec2().describe_network_interfaces().send().await?;

    for ni in res.network_interfaces() {
        let n = ni.tag_set.tag("Name");

        let mut r = Row::default();
        r.add_stror("id", ni.network_interface_id.as_deref(), "?");
        r.add_stror("name", n.as_deref(), "-");
        r.add_stror("type", ni.interface_type().map(|it| it.as_str()), "-");

        if let Some(assoc) = ni.association() {
            r.add_stror("eip", assoc.allocation_id.as_deref(), "-");
        } else {
            r.add_str("eip", "-");
        };

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

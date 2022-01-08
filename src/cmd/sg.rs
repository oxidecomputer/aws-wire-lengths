use crate::prelude::*;

pub async fn do_sg(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list security groups", cmd!(do_sg_ls))?;

    sel!(l).run().await
}

async fn do_sg_ls(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", 20, true);
    l.add_column("name", 28, true);
    l.add_column("vpc", WIDTH_VPC, true);
    l.add_column("desc", 32, false);
    l.add_column("fulldesc", 50, false);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s
        .ec2()
        .describe_security_groups(ec2::DescribeSecurityGroupsRequest {
            ..Default::default()
        })
        .await?;

    let x = Vec::new();
    for sg in res.security_groups.as_ref().unwrap_or(&x) {
        let mut r = Row::default();

        r.add_stror("id", &sg.group_id, "?");
        r.add_stror("name", &sg.group_name, "-");
        r.add_stror("vpc", &sg.vpc_id, "-");
        let desc = if let Some(desc) = sg.description.as_deref() {
            if let Some(name) = sg.group_name.as_deref() {
                desc.trim_start_matches(name)
            } else {
                desc
            }
            .trim()
        } else {
            "-"
        };
        r.add_str("desc", desc);
        r.add_stror("fulldesc", &sg.description, "-");

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

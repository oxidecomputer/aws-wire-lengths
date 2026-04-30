use crate::prelude::*;

pub async fn do_iam(mut l: Level<Stuff>) -> Result<()> {
    l.cmd("role", "manage IAM roles", cmd!(do_role))?;

    sel!(l).run().await
}

pub async fn do_role(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list IAM roles", cmd!(do_role_list))?;
    l.cmd("show", "show an IAM role", cmd!(do_role_show))?;

    sel!(l).run().await
}

async fn do_role_list(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", WIDTH_AROA, true);
    l.add_column("name", 60, true);
    l.add_column("arn", 130, false);
    l.add_column("path", 60, false);

    let a = no_args!(l);
    let s = l.context();
    let mut t = a.table();

    let res = s.iam().list_roles().send().await?;

    for role in res.roles() {
        let mut r = Row::default();
        r.add_str("id", role.role_id());
        r.add_str("name", role.role_name());
        r.add_str("arn", role.arn());
        r.add_str("path", role.path());
        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn do_role_show(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);
    if a.args().len() != 1 {
        bad_args!(l, "specify IAM role");
    }

    let s = l.context();

    let role = get_role_fuzzy(l.context(), &a.args()[0]).await?;

    /*
     * The role list does not populate all attributes of the role.  Fetch the
     * rest.
     */
    let role = s
        .iam()
        .get_role()
        .role_name(role.role_name())
        .send()
        .await?;
    let Some(role) = role.role() else {
        bail!("GetRole did not include a role?!");
    };

    println!("id: {}", role.role_id());
    println!("name: {}", role.role_name());
    println!("arn: {}", role.arn());
    println!("path: {}", role.path());
    if let Some(rlu) = role.role_last_used() {
        println!("last used: {:?} {:?}", rlu.region(), rlu.last_used_date());
    }
    if let Some(pb) = role.permissions_boundary() {
        println!(
            "permissions boundary: {:?} {:?}",
            pb.permissions_boundary_type(),
            pb.permissions_boundary_arn(),
        );
    }
    if let Some(desc) = role.description() {
        println!("description: {desc}");
    }
    if let Some(msd) = role.max_session_duration() {
        println!("max session duration: {msd}");
    }
    if !role.tags().is_empty() {
        println!("tags:");
        for t in role.tags() {
            println!("    {} -> {}", t.key(), t.value());
        }
    }

    for rp in s
        .iam()
        .list_role_policies()
        .role_name(role.role_name())
        .send()
        .await?
        .policy_names()
    {
        println!("policy name: {rp}");

        let rpol = s
            .iam()
            .get_role_policy()
            .role_name(role.role_name())
            .policy_name(rp)
            .send()
            .await?;
        let doc = pct_str::PctString::new(rpol.policy_document())?;
        println!("policy document:");
        println!(
            "{}",
            doc.decode()
                .lines()
                .map(|l| format!("    {l}\n"))
                .collect::<String>()
        );
    }

    Ok(())
}

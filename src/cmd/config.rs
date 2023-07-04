use crate::prelude::*;

pub async fn do_config(mut l: Level<Stuff>) -> Result<()> {
    l.cmd("serial", "manage serial console access", cmd!(do_serial))?;
    l.cmd(
        "rename",
        "change the Name tag on a resource",
        cmd!(do_rename),
    )?;

    sel!(l).run().await
}

async fn do_serial(mut l: Level<Stuff>) -> Result<()> {
    l.cmda(
        "enable",
        "on",
        "enable serial consoles",
        cmd!(do_serial_enable),
    )?;
    l.cmda(
        "disable",
        "off",
        "disable serial consoles",
        cmd!(do_serial_disable),
    )?;
    l.cmd(
        "get",
        "get serial console enable status",
        cmd!(do_serial_get),
    )?;

    sel!(l).run().await
}

async fn do_serial_disable(mut l: Level<Stuff>) -> Result<()> {
    no_args!(l);
    let s = l.context();

    let res = s.ec2().disable_serial_console_access().send().await?;

    if res
        .serial_console_access_enabled
        .ok_or_else(|| anyhow!("weird response"))?
    {
        bail!("tried to disable serial consoles, but they are still enabled");
    }

    Ok(())
}

async fn do_serial_enable(mut l: Level<Stuff>) -> Result<()> {
    no_args!(l);
    let s = l.context();

    let res = s.ec2().enable_serial_console_access().send().await?;

    if !res
        .serial_console_access_enabled
        .ok_or_else(|| anyhow!("weird response"))?
    {
        bail!("tried to enable serial consoles, but they are still disabled");
    }

    Ok(())
}

async fn do_serial_get(mut l: Level<Stuff>) -> Result<()> {
    no_args!(l);
    let s = l.context();

    let res = s.ec2().get_serial_console_access_status().send().await?;

    if res
        .serial_console_access_enabled
        .ok_or_else(|| anyhow!("weird response"))?
    {
        println!("enabled");
    } else {
        println!("disabled");
    }

    Ok(())
}

async fn do_rename(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("ID NEW_NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify resource ID and new name");
    }

    s.ec2()
        .create_tags()
        .resources(a.args().get(0).unwrap())
        .tags(
            aws_sdk_ec2::types::Tag::builder()
                .key("Name")
                .value(a.args().get(1).unwrap())
                .build(),
        )
        .send()
        .await?;

    Ok(())
}

use crate::prelude::*;

pub async fn do_config(mut l: Level<Stuff>) -> Result<()> {
    l.cmd("serial", "manage serial console access", cmd!(do_serial))?;

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

    let res = s
        .ec2()
        .disable_serial_console_access(
            ec2::DisableSerialConsoleAccessRequest::default(),
        )
        .await?;

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

    let res = s
        .ec2()
        .enable_serial_console_access(
            ec2::EnableSerialConsoleAccessRequest::default(),
        )
        .await?;

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

    let res = s
        .ec2()
        .get_serial_console_access_status(
            ec2::GetSerialConsoleAccessStatusRequest::default(),
        )
        .await?;

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

use crate::prelude::*;

use aws_sdk_ebs::primitives::DateTimeFormat;

pub async fn do_role(mut l: Level<Stuff>) -> Result<()> {
    l.cmd("assume", "assume a role", cmd!(do_role_assume))?;

    sel!(l).run().await
}

async fn do_role_assume(mut l: Level<Stuff>) -> Result<()> {
    l.reqopt("", "role", "ARN of role to assume", "ARN");
    l.reqopt("", "session", "name of session", "NAME");
    l.reqopt("", "mfa", "ARN of MFA token", "SERIAL");
    l.reqopt("", "token", "MFA token code", "CODE");
    l.optflag("", "shell", "emit shell commands to configure environment");

    let a = no_args!(l);

    let res = l
        .context()
        .sts()
        .assume_role()
        .duration_seconds(3600)
        .role_arn(a.opts().opt_str("role").unwrap())
        .role_session_name(a.opts().opt_str("session").unwrap())
        .serial_number(a.opts().opt_str("mfa").unwrap())
        .token_code(a.opts().opt_str("token").unwrap())
        .send()
        .await?;

    if a.opts().opt_present("shell") {
        if let Some(c) = res.credentials {
            println!("AWS_ACCESS_KEY_ID='{}'; ", c.access_key_id());
            println!(
                "AWS_CREDENTIAL_EXPIRATION='{}'; ",
                c.expiration().fmt(DateTimeFormat::DateTime).unwrap(),
            );
            println!("AWS_SECRET_ACCESS_KEY='{}'; ", c.secret_access_key());
            println!("AWS_SESSION_TOKEN='{}'; ", c.session_token());
            for v in [
                "ACCESS_KEY_ID",
                "CREDENTIAL_EXPIRATION",
                "SECRET_ACCESS_KEY",
                "SESSION_TOKEN",
            ] {
                println!("export AWS_{}; ", v);
            }
        }
    } else {
        println!("res: {:#?}", res);
    }
    Ok(())
}

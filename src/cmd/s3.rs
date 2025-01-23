use std::time::{SystemTime, UNIX_EPOCH};

use aws_sdk_s3::error::SdkError;

use crate::prelude::*;

async fn do_bucket_ls(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("name", 48, true);
    l.add_column("creation", WIDTH_UTC, true);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s.s3().list_buckets().send().await?;

    for b in res.buckets() {
        let mut r = Row::default();

        r.add_stror("name", b.name.as_deref(), "?");
        r.add_stror("creation", b.creation_date.as_utc().as_deref(), "-");

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn do_bucket(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list buckets", cmd!(do_bucket_ls))?;
    l.cmd("show", "show detail about a bucket", cmd!(do_bucket_show))?;
    l.cmd("create", "create a bucket", cmd!(do_bucket_create))?;
    l.cmd(
        "uploads",
        "show unfinished multipart uploads for a bucket",
        cmd!(do_bucket_uploads),
    )?;

    sel!(l).run().await
}

async fn do_bucket_create(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("BUCKET"));

    let a = args!(l);
    let s = l.context();

    if a.args().is_empty() {
        bad_args!(l, "specify a bucket name to create");
    }

    let bucket = a.args().get(0).unwrap();

    let res = s
        .s3()
        .create_bucket()
        .object_ownership(
            aws_sdk_s3::types::ObjectOwnership::BucketOwnerEnforced,
        )
        .create_bucket_configuration(
            aws_sdk_s3::types::CreateBucketConfiguration::builder()
                .location_constraint(
                    aws_sdk_s3::types::BucketLocationConstraint::from(
                        s.region_s3().to_string().as_str(),
                    ),
                )
                .build(),
        )
        .bucket(bucket)
        .send()
        .await?;

    println!("{:#?}", res);
    Ok(())
}

async fn do_bucket_show(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("BUCKET"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify exactly one bucket name to examine");
    }

    let bucket = a.args().get(0).unwrap();

    macro_rules! emit {
        ($name:literal, $expr:expr) => {
            println!("    {:30} {:?}", format!("{}:", $name), $expr);
        };
    }

    match s
        .s3()
        .get_bucket_policy_status()
        .bucket(bucket)
        .send()
        .await
    {
        Ok(res) => match res.policy_status() {
            Some(v) => {
                println!("policy status:");
                emit!("is public", v.is_public());
            }
            None => println!("no policy status for bucket?!"),
        },
        Err(SdkError::ServiceError(err))
            if err.err().meta().code() == Some("NoSuchBucketPolicy") =>
        {
            println!("no policy status for bucket");
        }
        Err(e) => {
            return Err(e.into());
        }
    };
    println!();

    match s.s3().get_public_access_block().bucket(bucket).send().await {
        Ok(res) => match res.public_access_block_configuration() {
            Some(v) => {
                println!("public access block:");
                emit!("block public ACLs", v.block_public_acls());
                emit!("ignore public ACLs", v.ignore_public_acls());
                emit!("block public policy", v.block_public_policy());
                emit!("restrict public buckets", v.restrict_public_buckets());
            }
            None => println!("no public access block for bucket?!"),
        },
        Err(SdkError::ServiceError(err))
            if err.err().meta().code()
                == Some("NoSuchPublicAccessBlockConfiguration") =>
        {
            println!("no public access block for bucket");
        }
        Err(e) => {
            return Err(e.into());
        }
    };
    println!();

    match s.s3().get_bucket_policy().bucket(bucket).send().await {
        Ok(res) => match res.policy() {
            Some(policy) => {
                /*
                 * Pretty-print the policy document as JSON:
                 */
                let policy: serde_json::Value = serde_json::from_str(policy)?;
                let out = serde_json::to_string_pretty(&policy)?
                    .lines()
                    .map(|l| format!("    {l}\n"))
                    .collect::<String>();
                print!("policy:\n{out}");
            }
            None => println!("no policy for bucket?!"),
        },
        Err(SdkError::ServiceError(err))
            if err.err().meta().code() == Some("NoSuchBucketPolicy") =>
        {
            println!("no policy for bucket");
        }
        Err(e) => {
            return Err(e.into());
        }
    };
    println!();

    let res = s.s3().get_bucket_versioning().bucket(bucket).send().await?;
    println!("versioning:");
    emit!("status", res.status());
    emit!("mfa_delete", res.mfa_delete());
    println!();

    match s
        .s3()
        .get_bucket_ownership_controls()
        .bucket(bucket)
        .send()
        .await
    {
        Ok(res) => match res.ownership_controls() {
            Some(oc) => {
                println!("ownership control rules:");
                for r in oc.rules() {
                    let out = format!("{r:#?}")
                        .lines()
                        .map(|l| format!("    {l}\n"))
                        .collect::<String>();
                    print!("{out}");
                }
            }
            None => println!("no ownership controls for bucket?!"),
        },
        Err(SdkError::ServiceError(err))
            if err.err().meta().code()
                == Some("OwnershipControlsNotFoundError") =>
        {
            println!("no ownership controls for bucket");
        }
        Err(e) => {
            return Err(e.into());
        }
    };
    println!();

    match s
        .s3()
        .get_bucket_lifecycle_configuration()
        .bucket(bucket)
        .send()
        .await
    {
        Ok(res) => {
            println!("lifecycle rules:");
            for r in res.rules() {
                let out = format!("{r:#?}")
                    .lines()
                    .map(|l| format!("    {l}\n"))
                    .collect::<String>();
                print!("{out}");
            }
        }
        Err(SdkError::ServiceError(err))
            if err.err().meta().code()
                == Some("NoSuchLifecycleConfiguration") =>
        {
            println!("no lifecycle rules for bucket");
        }
        Err(e) => {
            return Err(e.into());
        }
    };
    println!();

    Ok(())
}

async fn do_bucket_uploads(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("BUCKET"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify exactly one bucket name to examine");
    }

    let bucket = a.args().get(0).unwrap();

    let mut upload_id_marker = None;
    loop {
        let mpus = s
            .s3()
            .list_multipart_uploads()
            .bucket(bucket)
            .set_upload_id_marker(upload_id_marker.clone())
            .send()
            .await?;

        for mpu in mpus.uploads() {
            let Some(key) = mpu.key() else {
                eprintln!("WARNING: upload without key!");
                continue;
            };

            let age_secs = mpu
                .initiated()
                .map(|dt| {
                    let when: u64 = dt.to_millis().unwrap().try_into().unwrap();
                    let now: u64 = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis()
                        .try_into()
                        .unwrap();

                    (if when <= now { now - when } else { 0 }) / 1000
                })
                .unwrap_or(0);

            println!("{age_secs:12} {key}");
        }

        /*
         * Only request another page if we were given a non-empty marker:
         */
        if let Some(next) = mpus.next_upload_id_marker() {
            if next.is_empty() {
                break;
            }

            upload_id_marker = Some(next.to_string());
        } else {
            break;
        }
    }

    Ok(())
}

async fn do_object_tree(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("BUCKET [PREFIX]"));

    l.optflag("N", "", "output ncdu export format");

    let a = args!(l);
    let s = l.context();

    if a.args().is_empty() {
        bad_args!(l, "specify a bucket name to list");
    } else if a.args().len() > 2 {
        bad_args!(l, "too many arguments");
    }

    let bucket = a.args().get(0).cloned().unwrap();
    let prefix = a.args().get(1).cloned();
    let ncdu = a.opts().opt_present("N");

    let mut list = s
        .s3()
        .list_objects_v2()
        .bucket(&bucket)
        .set_prefix(prefix)
        .into_paginator()
        .page_size(1000)
        .send();

    let mut stack = Vec::new();
    fn indent(n: usize) -> String {
        let mut out = String::new();
        while out.len() < n * 4 {
            out.push_str("    ");
        }
        out
    }

    if ncdu {
        println!(
            "{}",
            r#"[1,0,{"progname":"aws-wire-lengths","progver":"0"},"#
        );

        /*
         * Emit a "root" directory entry for the bucket itself:
         */
        println!(r#"[{{"name":"{}"}}"#, bucket);
    }

    while let Some(res) = list.next().await.transpose()? {
        for o in res.contents() {
            /*
             * We are only able to store and enumerate objects in S3, so we
             * simulate directories by splitting on the delimiter character.
             * The last component is, therefore, always a "file".
             */
            let key = o.key().ok_or_else(|| anyhow!("no key?"))?;
            let levels = key.split('/').collect::<Vec<_>>();

            while stack.len() > levels.len() - 1 {
                stack.pop().unwrap();
                if ncdu {
                    println!("]");
                }
            }
            for i in 0..(levels.len() - 1) {
                if i < stack.len() {
                    if stack[i] == levels[i] {
                        /*
                         * We are already in this directory.
                         */
                        continue;
                    } else {
                        /*
                         * This stack entry, and everything to the right, is
                         * wrong and must be discarded.
                         */
                        while stack.len() > i {
                            stack.pop().unwrap();
                            if ncdu {
                                println!("]");
                            }
                        }
                    }
                }

                /*
                 * This is a new directory!
                 */
                if !ncdu {
                    println!("{}{}/", indent(stack.len()), levels[i]);
                } else {
                    println!(r#",[{{"name":"{}"}}"#, levels[i]);
                }
                stack.push(levels[i].to_string());
            }

            if !ncdu {
                println!("{}{}", indent(stack.len()), levels[levels.len() - 1]);
            } else {
                println!(
                    r#",{{"name":"{}","asize":{},"dsize":{}}}"#,
                    levels[levels.len() - 1],
                    o.size().unwrap_or_default(),
                    o.size().unwrap_or_default(),
                );
            }
        }
    }

    if ncdu {
        for _ in 0..stack.len() {
            print!("]");
        }
        println!("{}", r#"]]"#);
    }

    Ok(())
}

async fn do_object_ls(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("BUCKET [PREFIX]"));

    l.optflag("l", "", "include metadata in output");
    l.optflag("L", "", "include metadata in output");

    let a = args!(l);
    let s = l.context();

    if a.args().is_empty() {
        bad_args!(l, "specify a bucket name to list");
    } else if a.args().len() > 2 {
        bad_args!(l, "too many arguments");
    }

    let bucket = a.args().get(0).cloned().unwrap();
    let prefix = a.args().get(1).cloned();

    let mut list = s
        .s3()
        .list_objects_v2()
        .bucket(bucket)
        .set_prefix(prefix)
        .into_paginator()
        .page_size(1000)
        .send();

    while let Some(res) = list.next().await.transpose()? {
        for o in res.contents() {
            let key = o.key().ok_or_else(|| anyhow!("no key?"))?;
            let size = o.size();
            let mtime = o.last_modified.as_utc();
            let mtime = mtime.as_deref().unwrap_or("-");
            let etag = o.e_tag().unwrap_or("-");

            if a.opts().opt_present("L") {
                println!(
                    "{} {} {} {}",
                    size.unwrap_or_default(),
                    mtime,
                    etag,
                    key,
                );
            }
            if a.opts().opt_present("l") {
                println!("{} {} {}", size.unwrap_or_default(), mtime, key);
            } else {
                println!("{}", key);
            }
        }
    }

    Ok(())
}

async fn do_object_info(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("BUCKET KEY"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify a bucket name and an object key");
    }

    let bucket = a.args()[0].clone();
    let key = a.args()[1].clone();

    let res = s
        .s3()
        .head_object()
        .bucket(&bucket)
        .key(&key)
        .send()
        .await?;

    println!("{:#?}", res);

    let res = s
        .s3()
        .get_object_acl()
        .bucket(&bucket)
        .key(&key)
        .send()
        .await?;

    println!("{:#?}", res);

    Ok(())
}

async fn do_object_get(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("BUCKET KEY"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify a bucket name and an object key");
    }

    let bucket = a.args()[0].clone();
    let key = a.args()[1].clone();

    let mut res = s.s3().get_object().bucket(bucket).key(key).send().await?;

    let out = std::io::stdout();
    let mut out = out.lock();

    while let Some(chunk) = res.body.next().await.transpose()? {
        out.write_all(&chunk)?;
    }
    out.flush()?;

    Ok(())
}

async fn do_presign_get(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("BUCKET KEY"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify a bucket name and an object key");
    }

    let bucket = a.args()[0].clone();
    let key = a.args()[1].clone();

    let res = s
        .s3()
        .get_object()
        .bucket(bucket)
        .key(key)
        .presigned(
            aws_sdk_s3::presigning::PresigningConfig::builder()
                .expires_in(std::time::Duration::from_secs(600))
                .build()?,
        )
        .await?;

    println!("{}", res.uri());
    Ok(())
}

async fn do_object_rm(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("BUCKET KEY"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify a bucket name and an object key");
    }

    let bucket = a.args()[0].clone();
    let key = a.args()[1].clone();

    s.s3()
        .delete_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await?;

    Ok(())
}

async fn do_object_put(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("BUCKET KEY"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify a bucket name and an object key");
    }

    let bucket = a.args()[0].clone();
    let key = a.args()[1].clone();

    /*
     * Regrettably, one cannot just stream a file into S3 without knowing the
     * file size in advance.  A half-way solution would be to buffer and upload
     * 5MB chunks as a multipart upload, but of course that is not free and
     * automatic cleaning of the detritus requires some sort of bucket
     * configuration.
     *
     * For now, if it's a real file we will try and get the metadata.  Otherwise
     * we will buffer it all into memory (sigh).
     */
    let known_size = {
        /*
         * Borrow the stdin file descriptor so that we can fstat(2) it:
         */
        let stdin = std::io::stdin();
        let stdin = stdin.lock();
        let f = unsafe { File::from_raw_fd(stdin.as_raw_fd()) };
        let md = f.metadata()?;

        /*
         * We do not want to close stdin here, so get it back:
         */
        let _f = f.into_raw_fd();

        if md.is_file() {
            Some(md.len())
        } else {
            /*
             * If this not a file, we assume it is a pipe from some other
             * process.
             */
            None
        }
    };

    let (content_length, body) = if let Some(known_size) = known_size {
        let input = tokio::io::stdin();
        let body = aws_sdk_s3::primitives::SdkBody::from_body_1_x(
            StreamBody::new(tokio_util::io::ReaderStream::new(input)),
        );
        (known_size.try_into().unwrap(), body.into())
    } else {
        /*
         * It's a pipe.  Try to read all of the data into memory.
         */
        bail!("no pipes yet");
    };

    let res = s
        .s3()
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body)
        .content_length(content_length)
        .send()
        .await?;

    println!("res = {:?}", res);
    Ok(())
}

async fn do_presign(mut l: Level<Stuff>) -> Result<()> {
    l.cmd("get", "presign a GET request", cmd!(do_presign_get))?;

    sel!(l).run().await
}

async fn do_object(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list objects", cmd!(do_object_ls))?;
    l.cmd("tree", "list objects as a tree", cmd!(do_object_tree))?;
    l.cmd("get", "retrieve an object", cmd!(do_object_get))?;
    l.cmd("put", "store an object", cmd!(do_object_put))?;
    l.cmd("info", "inspect an object in detail", cmd!(do_object_info))?;
    l.cmda("delete", "rm", "delete an object", cmd!(do_object_rm))?;
    l.cmda(
        "presign",
        "pre",
        "presigned object requests",
        cmd!(do_presign),
    )?;

    sel!(l).run().await
}

pub async fn do_s3(mut l: Level<Stuff>) -> Result<()> {
    l.cmd("bucket", "bucket management", cmd!(do_bucket))?;
    l.cmda("object", "o", "object management", cmd!(do_object))?;

    sel!(l).run().await
}

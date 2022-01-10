use crate::prelude::*;

async fn do_bucket_ls(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("name", 48, true);
    l.add_column("creation", 24, true);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let res = s.s3().list_buckets().await?;

    let x = Vec::new();
    for b in res.buckets.as_ref().unwrap_or(&x) {
        let mut r = Row::default();

        r.add_stror("name", &b.name, "?");
        r.add_stror("creation", &b.creation_date, "-");

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn do_bucket(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list buckets", cmd!(do_bucket_ls))?;

    sel!(l).run().await
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

    let bucket = a.args()[0].clone();
    let prefix = a.args().get(1).cloned();
    let mut nct = None;

    loop {
        let res = s
            .s3()
            .list_objects_v2(s3::ListObjectsV2Request {
                bucket: bucket.clone(),
                continuation_token: nct.clone(),
                prefix: prefix.clone(),
                ..Default::default()
            })
            .await?;

        if let Some(c) = &res.contents {
            for o in c.iter() {
                let key = o.key.as_deref().ok_or_else(|| anyhow!("no key?"))?;
                let size = o.size.unwrap_or(0);
                let mtime = o.last_modified.as_deref().unwrap_or("-");
                let etag = o.e_tag.as_deref().unwrap_or("-");

                if a.opts().opt_present("L") {
                    println!("{} {} {} {}", size, mtime, etag, key);
                }
                if a.opts().opt_present("l") {
                    println!("{} {} {}", size, mtime, key);
                } else {
                    println!("{}", key);
                }
            }
        }

        nct = res.next_continuation_token;
        if nct.is_none() {
            break;
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
        .get_object_acl(s3::GetObjectAclRequest {
            bucket,
            key,
            ..Default::default()
        })
        .await?;

    println!("res = {:#?}", res);
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

    let res = s
        .s3()
        .get_object(s3::GetObjectRequest {
            bucket,
            key,
            ..Default::default()
        })
        .await?;

    if let Some(body) = res.body {
        let mut r = body.into_async_read();
        let mut buf = BytesMut::with_capacity(64 * 1024);
        let out = std::io::stdout();
        let mut out = out.lock();

        loop {
            buf.clear();
            let sz = r.read_buf(&mut buf).await?;
            if sz == 0 {
                return Ok(());
            }

            out.write_all(&buf)?;
        }
    } else {
        bail!("no body?");
    }
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
        .delete_object(s3::DeleteObjectRequest {
            bucket,
            key,
            ..Default::default()
        })
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
        f.into_raw_fd();

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
        let stree = tokio_util::io::ReaderStream::new(input);
        (
            Some(known_size as i64),
            Some(rusoto_core::ByteStream::new(stree)),
        )
    } else {
        /*
         * It's a pipe.  Try to read all of the data into memory.
         */
        bail!("no pipes yet");
    };

    let res = s
        .s3()
        .put_object(s3::PutObjectRequest {
            bucket,
            key,
            body,
            content_length,
            ..Default::default() //content_md5: (),
        })
        .await?;

    println!("res = {:?}", res);
    Ok(())
}

async fn do_object(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list objects", cmd!(do_object_ls))?;
    l.cmd("get", "retrieve an object", cmd!(do_object_get))?;
    l.cmd("put", "store an object", cmd!(do_object_put))?;
    l.cmd("info", "inspect an object in detail", cmd!(do_object_info))?;
    l.cmda("delete", "rm", "delete an object", cmd!(do_object_rm))?;

    sel!(l).run().await
}

pub async fn do_s3(mut l: Level<Stuff>) -> Result<()> {
    l.cmd("bucket", "bucket management", cmd!(do_bucket))?;
    l.cmda("object", "o", "object management", cmd!(do_object))?;

    sel!(l).run().await
}

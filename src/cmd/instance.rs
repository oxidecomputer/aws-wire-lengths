use aws_sdk_ebs::error::SdkError;
use aws_sdk_ec2::types::{
    BlockDeviceMapping, EbsBlockDevice, Filter,
    InstanceNetworkInterfaceSpecification, InstanceType, Tag, TagSpecification,
};
use aws_sdk_ec2instanceconnect as ec2ic;
use ec2ic::operation::send_serial_console_ssh_public_key::SendSerialConsoleSSHPublicKeyError;

use crate::prelude::*;

pub async fn do_instance(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list instances", cmd!(info))?;
    l.hcmd("dump", "dump info about an instance", cmd!(dump))?;
    l.cmd("ip", "get IP address for instance", cmd!(ip))?;
    l.cmd("start", "start an instance", cmd!(start))?;
    l.cmd("reboot", "reboot an instance", cmd!(reboot))?;
    l.cmd("stop", "stop an instance", cmd!(stop))?;
    l.cmd("resize", "change insance type", cmd!(resize))?;
    l.cmd("protect", "enable termination protection", cmd!(protect))?;
    l.cmd(
        "unprotect",
        "disable termination protection",
        cmd!(unprotect),
    )?;
    l.cmd("spoof", "disable source/destination check", cmd!(spoof))?;
    l.cmd("nospoof", "enable source/destination check", cmd!(nospoof))?;
    l.cmd("create", "create an instance", cmd!(create_instance))?;
    l.cmd("destroy", "destroy an instance", cmd!(destroy))?;
    l.cmda(
        "diag",
        "nmi",
        "send diagnostic interrupt to instance",
        cmd!(nmi),
    )?;
    l.cmd(
        "console",
        "connect to the serial console of a guest",
        cmd!(sercons),
    )?;
    l.cmd(
        "volumes",
        "show volumes attached to this instance",
        cmd!(volumes),
    )?;

    sel!(l).run().await
}

async fn create_instance(mut l: Level<Stuff>) -> Result<()> {
    l.optopt("n", "name", "instance name", "NAME");
    l.optopt("i", "image", "image (AMI)", "AMI_ID");
    l.optopt("t", "type", "instance type", "TYPE");
    l.optopt("k", "key", "SSH key name", "KEY_NAME");
    l.optopt("s", "sg", "security group ID", "SG_ID");
    l.optopt("S", "subnet", "subnet ID", "SUBNET_ID");
    l.optopt("u", "userdata", "userdata (in plain text)", "DATA");
    l.optopt("d", "disksize", "root disk size (GB)", "GIGABYTES");
    l.optopt("f", "file", "defaults TOML file to use", "PATH");
    l.optflag("p", "public-ip", "request a public IP");

    let a = args!(l);

    /*
     * If an instance defaults file was provided, load it now:
     */
    let defs: HashMap<String, String> = if let Some(p) = a.opts().opt_str("f") {
        let mut f = File::open(&p)?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        toml::from_str(&s)?
    } else {
        HashMap::new()
    };

    let fetchopt = |n: &str| -> Option<String> {
        if let Some(v) = a.opts().opt_str(n) {
            Some(v)
        } else {
            defs.get(n).map(|v| v.to_string())
        }
    };
    let fetch = |n: &str| -> Result<String> {
        if let Some(v) = fetchopt(n) {
            Ok(v)
        } else {
            bad_args!(l, "must specify option \"{}\"", n);
        }
    };
    let fetch_u32 = |n: &str| -> Result<u32> {
        match fetch(n)?.parse::<u32>() {
            Ok(v) => Ok(v),
            Err(e) => {
                bad_args!(l, "option \"{}\" must be a u32: {:?}", n, e);
            }
        }
    };
    let fetchopt_bool = |n: &str| -> Result<Option<bool>> {
        Ok(if a.opts().opt_present(n) {
            Some(true)
        } else if let Some(v) = fetchopt(n) {
            Some(match v.as_str() {
                "true" => true,
                "false" => false,
                x => bail!("invalid bool for \"{}\": {:?}", n, x),
            })
        } else {
            None
        })
    };

    let mut tags = HashMap::new();
    tags.insert("Name".to_string(), fetch("name")?);

    let io = InstanceOptions {
        ami_id: fetch("image")?,
        type_name: fetch("type")?,
        key_name: fetch("key")?,
        tags,
        root_size_gb: fetch_u32("disksize")?,
        subnet_id: fetch("subnet")?,
        sg_id: fetch("sg")?,
        user_data: fetchopt("userdata"),
        public_ip: fetchopt_bool("public-ip")?,
    };

    let id = i_create_instance(l.context(), &io).await?;
    println!("CREATED INSTANCE {}", id);

    Ok(())
}

async fn info(mut l: Level<Stuff>) -> Result<()> {
    l.optopt("V", "vpc", "filter instances by VPC name or ID", "VPC");

    // XXX l.optmulti("T", "", "specify a tag as an extra column", "TAG");

    l.add_column("launch", 24, false);
    l.add_column("id", 19, true);
    l.add_column("name", 28, true);
    l.add_column("ip", 15, true);
    l.add_column("state", 16, true);
    l.add_column("type", 12, false);
    l.add_column("az", WIDTH_AZ, false);
    l.add_column("key", 20, false);
    // XXX for tag in s.args.opt_strs("T") {
    // XXX     l.add_column(&tag, 20, true);
    // XXX }

    let a = args!(l);
    let mut t = a.table();

    if !a.args().is_empty() {
        if a.opts().opt_present("vpc") {
            bad_args!(l, "cannot use -V for specific instance lookup");
        }

        for n in a.args().iter() {
            let i = get_instance_fuzzy(l.context(), n).await?;

            let mut r = Row::default();
            r.add_str("id", &i.id);
            r.add_stror("name", i.name.as_deref(), "-");
            r.add_str("launch", &i.launch);
            r.add_stror("ip", i.ip.as_deref(), "-");
            r.add_str("state", &i.state);
            r.add_stror("az", i.az.as_deref(), "-");
            r.add_stror("key", i.raw.key_name(), "-");
            // XXX for tag in s.args.opt_strs("T") {
            // XXX     r.add_str(&tag, "-"); /* XXX */
            // XXX }
            t.add_row(r);
        }
    } else {
        let s = l.context();

        let filters = if let Some(vpc) = a.opts().opt_str("vpc") {
            let vpc = get_vpc_fuzzy(s, &vpc).await?;
            Some(vec![Filter::builder()
                .name("vpc-id")
                .values(vpc.vpc_id.unwrap())
                .build()])
        } else {
            None
        };

        let res = s
            .ec2()
            .describe_instances()
            .set_filters(filters)
            .send()
            .await?;

        for r in res.reservations() {
            for i in r.instances() {
                let mut r = Row::default();

                let pubip = i.public_ip_address.as_deref();
                let privip = i.private_ip_address.as_deref();

                r.add_str(
                    "type",
                    i.instance_type
                        .as_ref()
                        .map(|it| it.as_str())
                        .unwrap_or("-"),
                );
                r.add_str("id", i.instance_id.as_deref().unwrap());
                r.add_stror("name", i.tags.tag("Name").as_deref(), "-");
                let launch = i.launch_time.map(|dt| {
                    /*
                     * XXX
                     */
                    dt.fmt(aws_sdk_ebs::primitives::DateTimeFormat::DateTime)
                        .unwrap()
                });
                r.add_stror("launch", launch.as_deref(), "-");
                r.add_str("ip", pubip.unwrap_or_else(|| privip.unwrap_or("-")));
                r.add_str(
                    "state",
                    i.state
                        .as_ref()
                        .map(|s| s.name().map(|n| n.as_str()))
                        .flatten()
                        .unwrap_or("-"),
                );
                r.add_stror(
                    "az",
                    i.placement
                        .as_ref()
                        .and_then(|p| p.availability_zone.as_deref()),
                    "-",
                );
                r.add_stror("key", i.key_name(), "-");

                // XXX for tag in s.args.opt_strs("T") {
                // XXX     r.add_stror(&tag, &i.tags.tag(&tag), "-");
                // XXX }

                t.add_row(r);
            }
        }
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn start(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);
    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("starting instance: {:?}", i);

    start_instance(l.context(), &i.id).await?;

    println!("all done!");

    Ok(())
}

async fn nmi(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("sending diagnostic interrupt to instance: {:?}", i);

    s.ec2()
        .send_diagnostic_interrupt()
        .instance_id(i.id)
        .send()
        .await?;

    println!("all done!");

    Ok(())
}

async fn sercons(mut l: Level<Stuff>) -> Result<()> {
    l.optflag("S", "start", "start the instance before we try to connect");

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let start = a.opts().opt_present("start");

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    /*
     * To access an EC2 serial console, you must first push an SSH key to the
     * remote system.  That key will be useable for 60 seconds to initiate an
     * SSH connection to the concentrator service.  At time of writing, the
     * serial console service only supports RSA keys; no other types.
     *
     * To make this easier, we will generate an ephemeral key and
     * tell ssh(1) about it.  Regrettably EC2 Instance Connect requires a
     * 2048 bit key, even though it has a 60 second lifetime and a 1024 bit key,
     * which would be substantially cheaper to generate, would seem fine.
     * The API is also very picky about how many times you can push a key,
     * even the same key, often throwing an error like "Too many active serial
     * console sessions." which is neither helpful nor even strictly true.
     *
     * We know the expected SSH host key for at least some of the servers, so we
     * can prepopulate a special known_hosts file.
     */
    let dir = if let Some(mut dir) = dirs_next::cache_dir() {
        dir.push("aws-wire-lengths");
        dir
    } else {
        bail!("could not find user cache directory");
    };
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&dir)?;

    let path_knownhosts = {
        let mut path_knownhosts = dir.clone();
        path_knownhosts.push("known_hosts");
        path_knownhosts
    };

    let lines = match std::fs::File::open(&path_knownhosts) {
        Ok(mut f) => {
            let mut s = String::new();
            f.read_to_string(&mut s)?;
            s.lines().map(|s| s.to_string()).collect::<Vec<_>>()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => bail!("opening {:?}: {:?}", path_knownhosts, e),
    };

    /*
     * The list of known hosts and their keys is included in the executable at
     * build time:
     */
    for want in include_str!("../../known_hosts.txt").lines() {
        if lines.iter().any(|l| l == want) {
            /*
             * This key already appears in our local file.
             */
            continue;
        }

        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&path_knownhosts)?;
        f.write_all(format!("{}\n", want).as_bytes())?;
        f.flush()?;
    }

    /*
     * Check to see if we have already generated an SSH key.  We will avoid
     * regenerating the key if it was generated in the last hour.
     */
    let path_pemfile = {
        let mut path_pemfile = dir.clone();
        path_pemfile.push("sercons.pem");
        path_pemfile
    };

    let key = match std::fs::File::open(&path_pemfile) {
        Ok(mut f) => {
            let mut s = String::new();
            if let Err(e) = f.read_to_string(&mut s) {
                eprintln!("WARNING: reading {:?}: {:?}", path_pemfile, e);
                None
            } else {
                match rsa::RsaPrivateKey::from_pkcs8_pem(&s) {
                    Ok(key) => {
                        if let Ok(age) = std::time::SystemTime::now()
                            .duration_since(f.metadata()?.modified()?)
                        {
                            if age.as_secs() < 3600 {
                                Some(key)
                            } else {
                                /*
                                 * Old key, so regenerate.
                                 */
                                None
                            }
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "WARNING: parsing {:?}: {:?}",
                            path_pemfile, e
                        );
                        None
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            eprintln!("WARNING: opening {:?}: {:?}", path_pemfile, e);
            None
        }
    };

    let key = if let Some(key) = key {
        key
    } else {
        eprintln!("INFO: generating a new SSH key...");
        let key = rsa::RsaPrivateKey::new(&mut thread_rng(), 2048)?;
        let privkey = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path_pemfile)?;
        f.write_all(privkey.to_string().as_bytes())?;
        f.flush()?;
        key
    };

    /*
     * Could not see an easy crate for emitting the OpenSSH style public key
     * format, so we'll do it here by hand.
     *
     * The format is:
     *
     *  string  "ssh-rsa"
     *  bigint  e
     *  bigint  n
     *
     * Both data types are length-prefixed with a network order 32-bit unsigned
     * integer, and then just consist of the bytes of the string or the network
     * ordered bytes of the integer.  This packed binary layout is then
     * base64-encoded.
     *
     * Note that we add an extra 0 on the significant end of the "n" field, in
     * order that it not be mis-interpreted as a very large and very negative
     * value.
     */
    let pubkey = key.to_public_key();
    let mut raw = Vec::<u8>::new();
    let hdr = "ssh-rsa";
    raw.extend_from_slice(&(hdr.as_bytes().len() as u32).to_be_bytes());
    raw.extend_from_slice(hdr.as_bytes());

    let e = pubkey.e().to_bytes_be();
    raw.extend_from_slice(&(e.len() as u32).to_be_bytes());
    raw.extend_from_slice(&e);

    let n = pubkey.n().to_bytes_be();
    raw.extend_from_slice(&((n.len() as u32) + 1).to_be_bytes());
    raw.push(0);
    raw.extend_from_slice(&n);

    let pubkey = format!("ssh-rsa {}", base64_encode(&raw));

    if start {
        start_instance(s, &i.id).await?;
    }

    /*
     * Try to push the key to the server.
     */
    let mut warned = false;
    let mut nostartmsg = false;
    loop {
        match s
            .ic()
            .send_serial_console_ssh_public_key()
            .instance_id(&i.id)
            .ssh_public_key(&pubkey)
            .send()
            .await
        {
            Ok(x) => {
                if !x.success() {
                    /*
                     * This is a bad API and it should feel bad.
                     */
                    eprintln!("WARNING: key push request did not succeed?");
                }
                break;
            }
            Err(SdkError::ServiceError(err)) => {
                use SendSerialConsoleSSHPublicKeyError::*;

                match err.err() {
                    ThrottlingException(e) => {
                        /*
                         * Sigh.
                         */
                        eprintln!("WARNING: throttle? {}", e);
                        std::thread::sleep(Duration::from_secs(2));
                    }
                    SerialConsoleSessionLimitExceededException(e) => {
                        if !warned {
                            eprintln!("WARNING: {} (retrying)", e);
                            warned = true;
                        }

                        std::thread::sleep(Duration::from_secs(3));
                    }
                    Ec2InstanceStateInvalidException(e) => {
                        if let Some(msg) = e.message() {
                            if msg.contains("stopped instance")
                                || msg.contains("pending state")
                            {
                                /*
                                 * This looks like the instance is not
                                 * started.  So that we can try to catch it
                                 * as soon as possible in boot, poll waiting
                                 * for it to start.
                                 */
                                if !nostartmsg {
                                    eprintln!(
                                        "INFO: instance not running? \
                                        waiting to start..."
                                    );
                                    nostartmsg = true;
                                }

                                std::thread::sleep(Duration::from_secs(1));
                                continue;
                            }
                        }

                        bail!("SSH key push failure: {e}");
                    }
                    other => {
                        bail!("SSH key push failure: {other}");
                    }
                }
            }
            Err(e) => {
                bail!("SSH key push failure: {:?}", e);
            }
        }
    }

    if warned || nostartmsg {
        println!();
    }

    println!("Connecting to serial console.  Escape sequence is <Enter>#.");
    let err = std::process::Command::new("ssh")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            path_knownhosts.to_str().unwrap()
        ))
        .arg("-e")
        .arg("#")
        .arg("-i")
        .arg(path_pemfile)
        .arg(format!(
            "{}.port0@serial-console.ec2-instance-connect.{}.aws",
            i.id,
            s.region_ec2().to_string(),
        ))
        .exec();

    bail!("SSH exec error: {:?}", err);
}

async fn stop(mut l: Level<Stuff>) -> Result<()> {
    l.optflag("f", "", "force stop");

    let a = args!(l);

    let force = a.opts().opt_present("f");

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("stopping instance: {:?}", i);

    stop_instance(l.context(), &i.id, force).await?;

    println!("all done!");

    Ok(())
}

async fn reboot(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("rebooting instance: {:?}", i);

    s.ec2().reboot_instances().instance_ids(i.id).send().await?;

    println!("all done!");

    Ok(())
}

async fn spoof(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("enabling spoofing for instance: {:?}", i);

    instance_spoofing(l.context(), &i.id, true).await?;

    println!("all done!");

    Ok(())
}

async fn nospoof(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("disabling spoofing for instance: {:?}", i);

    instance_spoofing(l.context(), &i.id, false).await?;

    println!("all done!");

    Ok(())
}

async fn resize(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("INSTANCE TYPE"));
    l.optflag("E", "", "enable ENA for this instance");

    let a = args!(l);

    if a.args().len() != 2 {
        bail!("expect an instance and a new instance type");
    }

    let i = get_instance_fuzzy(l.context(), a.args().first().unwrap()).await?;

    change_instance_type(
        l.context(),
        &i.id,
        &a.args()[1],
        a.opts().opt_present("E"),
    )
    .await?;

    println!("all done!");

    Ok(())
}

async fn protect(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("protecting instance: {:?}", i);

    protect_instance(l.context(), &i.id, true).await?;

    println!("all done!");

    Ok(())
}

async fn unprotect(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("unprotecting instance: {:?}", i);

    protect_instance(l.context(), &i.id, false).await?;

    println!("all done!");

    Ok(())
}

async fn destroy(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);

    if a.args().len() != 1 {
        bail!("expect the name of just one instance");
    }

    let i = get_instance_fuzzy(l.context(), a.args().get(0).unwrap()).await?;

    println!("destroying instance: {:?}", i);

    destroy_instance(l.context(), &i.id).await?;

    println!("all done!");

    Ok(())
}

async fn ip(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);

    if a.args().len() != 1 {
        bail!("specify just one instance");
    }
    let n = a.args()[0].as_str();

    let i = get_instance_fuzzy(l.context(), n).await?;
    if let Some(ip) = i.ip {
        println!("{}", ip);
        Ok(())
    } else {
        bail!("no IP address for instance {} ({})", n, i.id);
    }
}

async fn volumes(mut l: Level<Stuff>) -> Result<()> {
    l.add_column("id", WIDTH_VOL, true);
    l.add_column("size", 7, true);
    l.add_column("flags", 5, true);
    l.add_column("state", 8, true);
    l.add_column("astate", 8, true);
    l.add_column("device", 6, true);
    l.add_column("name", 10, true);

    let a = args!(l);
    let s = l.context();
    let mut t = a.table();

    if a.args().len() != 1 {
        bail!("specify just one instance");
    }
    let n = a.args()[0].as_str();

    let i = get_instance_fuzzy(l.context(), n).await?;

    let res = s
        .ec2()
        .describe_volumes()
        .filters(
            aws_sdk_ec2::types::Filter::builder()
                .name("attachment.instance-id")
                .values(&i.id)
                .build(),
        )
        .send()
        .await?;

    for vol in res.volumes() {
        for att in vol.attachments() {
            let mut r = Row::default();

            let flags =
                [att.delete_on_termination.unwrap_or_default().as_flag("D")]
                    .join("");

            let size_gbs: u64 = vol.size().unwrap_or(0).try_into().unwrap();

            r.add_str("id", vol.volume_id().unwrap());
            r.add_str("flags", &flags);
            r.add_stror("name", vol.tags.tag("Name").as_deref(), "-");
            r.add_bytes(
                "size",
                size_gbs.checked_mul(1024 * 1024 * 1024).unwrap(),
            );
            r.add_stror("state", vol.state().map(|v| v.as_str()), "-");
            r.add_stror("astate", att.state().map(|a| a.as_str()), "-");
            r.add_str(
                "device",
                if let Some(dev) = att.device() {
                    dev.trim_start_matches("/dev/")
                } else {
                    "-"
                },
            );

            t.add_row(r);
        }
    }

    print!("{}", t.output()?);
    Ok(())
}

async fn dump(mut l: Level<Stuff>) -> Result<()> {
    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bail!("specify a single instance by name or ID");
    }
    let i = get_instance_fuzzy(s, &a.args()[0]).await?;

    println!("INSTANCE {}", i.id);

    let res = s
        .ec2()
        .describe_instance_attribute()
        .attribute("disableApiTermination".into())
        .instance_id(i.id)
        .send()
        .await?;

    if res
        .disable_api_termination
        .map(|v| v.value.unwrap_or_default())
        .unwrap_or_default()
    {
        println!("TERMINATION PROTECTION: yes");
    } else {
        println!("TERMINATION PROTECTION: no");
    }

    for sg in i.raw.security_groups() {
        if let Some((id, name)) =
            sg.group_id.as_deref().zip(sg.group_name().as_deref())
        {
            println!("SECURITY GROUP: {id} {name:?}");
        }
    }

    if let Some(vpc) = i.raw.vpc_id() {
        println!("VPC: {vpc}");
    }

    if let Some(subnet) = i.raw.subnet_id() {
        println!("SUBNET: {subnet}");
    }

    if let Some(ip) = i.raw.public_ip_address() {
        println!("PUBLIC ADDRESS: {ip}");
    }
    if let Some(ip) = i.raw.private_ip_address() {
        println!("PRIVATE ADDRESS: {ip}");
    }

    for ni in i.raw.network_interfaces() {
        let Some(id) = ni.network_interface_id() else {
            continue;
        };

        println!("NETWORK INTERFACE {id}:");

        if let Some(ip) = ni.private_ip_address() {
            println!("    PRIVATE IP: {ip}");
        }
    }

    println!("{:<34} {:<45}", "TAG", "VALUE");
    for t in i.tags.iter() {
        let k = if let Some(k) = t.key.as_deref() {
            k
        } else {
            continue;
        };
        let v = t.value.as_deref().unwrap_or("-");

        println!("{:<34} {:<45}", k, v);
    }

    Ok(())
}

struct InstanceOptions {
    ami_id: String,
    type_name: String,
    key_name: String,
    tags: HashMap<String, String>,
    root_size_gb: u32,
    subnet_id: String,
    sg_id: String,
    user_data: Option<String>,
    public_ip: Option<bool>,
}

async fn i_create_instance(s: &Stuff, io: &InstanceOptions) -> Result<String> {
    let tag_specifications = if !io.tags.is_empty() {
        let tags = io
            .tags
            .iter()
            .map(|(k, v)| Tag::builder().key(k).value(v).build())
            .collect::<Vec<_>>();
        Some(vec![TagSpecification::builder()
            .resource_type(aws_sdk_ec2::types::ResourceType::Instance)
            .set_tags(Some(tags))
            .build()])
    } else {
        None
    };

    let res = s
        .ec2()
        .run_instances()
        .image_id(&io.ami_id)
        .instance_type(InstanceType::try_from(&*io.type_name)?)
        .key_name(&io.key_name)
        .min_count(1)
        .max_count(1)
        .set_tag_specifications(tag_specifications)
        .block_device_mappings(
            BlockDeviceMapping::builder()
                .device_name("/dev/sda1")
                .ebs(
                    EbsBlockDevice::builder()
                        .volume_size(io.root_size_gb as i32)
                        .build(),
                )
                .build(),
        )
        .network_interfaces(
            InstanceNetworkInterfaceSpecification::builder()
                .device_index(0)
                .subnet_id(&io.subnet_id)
                .groups(&io.sg_id)
                .associate_public_ip_address(io.public_ip.unwrap_or_default())
                .build(),
        )
        .set_user_data(
            io.user_data.as_deref().map(|x| base64_encode(x.as_bytes())),
        )
        .send()
        .await?;

    let ids = res
        .instances()
        .iter()
        .filter_map(|i| i.instance_id().map(|s| s.to_string()))
        .collect::<Vec<_>>();

    if ids.len() != 1 {
        bail!("wanted one instance, got {:?}", ids);
    } else {
        Ok(ids[0].to_string())
    }
}

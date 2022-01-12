use crate::prelude::*;

pub async fn do_instance(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list instances", cmd!(info))?;
    l.hcmd("dump", "dump info about an instance", cmd!(dump))?;
    l.cmd("ip", "get IP address for instance", cmd!(ip))?;
    l.cmd("start", "start an instance", cmd!(start))?;
    l.cmd("reboot", "reboot an instance", cmd!(reboot))?;
    l.cmd("stop", "stop an instance", cmd!(stop))?;
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
        let mut buf = Vec::<u8>::new();
        f.read_to_end(&mut buf)?;
        toml::from_slice(buf.as_slice())?
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

    let mut tags = HashMap::new();
    tags.insert("Name".to_string(), fetch("name")?);

    let public_ip = if a.opts().opt_present("p") {
        Some(true)
    } else {
        None
    };

    let io = InstanceOptions {
        ami_id: fetch("image")?,
        type_name: fetch("type")?,
        key_name: fetch("key")?,
        tags,
        root_size_gb: fetch_u32("disksize")?,
        subnet_id: fetch("subnet")?,
        sg_id: fetch("sg")?,
        user_data: fetchopt("userdata"),
        public_ip,
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
            r.add_stror("name", &i.name, "-");
            r.add_str("launch", &i.launch);
            r.add_stror("ip", &i.ip, "-");
            r.add_str("state", &i.state);
            r.add_stror("az", &i.az, "-");
            // XXX for tag in s.args.opt_strs("T") {
            // XXX     r.add_str(&tag, "-"); /* XXX */
            // XXX }
            t.add_row(r);
        }
    } else {
        let s = l.context();

        let filters = if let Some(vpc) = a.opts().opt_str("vpc") {
            let vpc = get_vpc_fuzzy(s, &vpc).await?;
            Some(vec![ec2::Filter {
                name: Some("vpc-id".to_string()),
                values: Some(vec![vpc.vpc_id.unwrap()]),
            }])
        } else {
            None
        };

        let res = s
            .ec2()
            .describe_instances(ec2::DescribeInstancesRequest {
                filters,
                ..Default::default()
            })
            .await?;

        if let Some(r) = &res.reservations {
            for r in r.iter() {
                if let Some(i) = &r.instances {
                    for i in i.iter() {
                        let mut r = Row::default();

                        let pubip = i.public_ip_address.as_deref();
                        let privip = i.private_ip_address.as_deref();

                        r.add_stror("type", &i.instance_type, "-");
                        r.add_str("id", i.instance_id.as_deref().unwrap());
                        r.add_stror("name", &i.tags.tag("Name"), "-");
                        r.add_str("launch", i.launch_time.as_deref().unwrap());
                        r.add_str(
                            "ip",
                            pubip.unwrap_or_else(|| privip.unwrap_or("-")),
                        );
                        r.add_str(
                            "state",
                            i.state.as_ref().unwrap().name.as_deref().unwrap(),
                        );
                        r.add_stror(
                            "az",
                            &i.placement.as_ref().map(|p| {
                                p.availability_zone
                                    .as_ref()
                                    .unwrap()
                                    .to_string()
                            }),
                            "-",
                        );

                        // XXX for tag in s.args.opt_strs("T") {
                        // XXX     r.add_stror(&tag, &i.tags.tag(&tag), "-");
                        // XXX }

                        t.add_row(r);
                    }
                }
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
        .send_diagnostic_interrupt(ec2::SendDiagnosticInterruptRequest {
            instance_id: i.id.to_string(),
            ..Default::default()
        })
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
        let privkey = key.to_pkcs8_pem()?;
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

    let pubkey =
        format!("ssh-rsa {}", base64::encode_config(raw, base64::STANDARD));

    if start {
        start_instance(s, &i.id).await?;
    }

    /*
     * Try to push the key to the server.
     */
    let mut warned = false;
    let mut nostartmsg = false;
    loop {
        use ec2ic::SendSerialConsoleSSHPublicKeyError::*;

        match s
            .ic()
            .send_serial_console_ssh_public_key(
                ec2ic::SendSerialConsoleSSHPublicKeyRequest {
                    instance_id: i.id.to_string(),
                    ssh_public_key: pubkey.to_string(),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(x) => {
                if !x.success.unwrap_or_default() {
                    /*
                     * This is a bad API and it should feel bad.
                     */
                    eprintln!("WARNING: key push request did not succeed?");
                }
                break;
            }
            Err(RusotoError::Service(Throttling(e))) => {
                /*
                 * Sigh.
                 */
                eprintln!("WARNING: throttle? {}", e);
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(RusotoError::Unknown(res)) => {
                let b = res.body_as_str();

                if res.status == 400
                    && (b.contains("stopped instance")
                        || b.contains("pending state"))
                {
                    /*
                     * This looks like the instance is not started.  So that we
                     * can try to catch it as soon as possible in boot, poll
                     * waiting for it to start.
                     */
                    if !nostartmsg {
                        eprintln!(
                            "INFO: instance not running? waiting to start..."
                        );
                        nostartmsg = true;
                    }

                    std::thread::sleep(Duration::from_secs(1));
                } else {
                    bail!("SSH key push failure: {}", res.body_as_str());
                }
            }
            Err(RusotoError::Service(SerialConsoleSessionLimitExceeded(e))) => {
                if !warned {
                    eprintln!("WARNING: {} (retrying)", e);
                    warned = true;
                }

                std::thread::sleep(Duration::from_secs(3));
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
            s.region_ec2().name()
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

    s.ec2()
        .reboot_instances(ec2::RebootInstancesRequest {
            instance_ids: vec![i.id.to_string()],
            ..Default::default()
        })
        .await?;

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
        .describe_instance_attribute(ec2::DescribeInstanceAttributeRequest {
            attribute: "disableApiTermination".to_string(),
            instance_id: i.id.to_string(),
            ..Default::default()
        })
        .await?;

    if res
        .disable_api_termination
        .unwrap_or_default()
        .value
        .unwrap_or_default()
    {
        println!("TERMINATION PROTECTION: yes");
    } else {
        println!("TERMINATION PROTECTION: no");
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
        let mut tags = Vec::new();
        for (k, v) in io.tags.iter() {
            tags.push(ec2::Tag {
                key: ss(k.as_str()),
                value: ss(v.as_str()),
            });
        }
        Some(vec![ec2::TagSpecification {
            resource_type: ss("instance"),
            tags: Some(tags),
        }])
    } else {
        None
    };

    let rir = ec2::RunInstancesRequest {
        image_id: ss(&io.ami_id),
        instance_type: ss(&io.type_name),
        key_name: ss(&io.key_name),
        min_count: 1,
        max_count: 1,
        tag_specifications,
        block_device_mappings: Some(vec![ec2::BlockDeviceMapping {
            device_name: ss("/dev/sda1"),
            ebs: Some(ec2::EbsBlockDevice {
                volume_size: Some(io.root_size_gb as i64),
                ..Default::default()
            }),
            ..Default::default()
        }]),
        network_interfaces: Some(vec![
            ec2::InstanceNetworkInterfaceSpecification {
                device_index: Some(0),
                subnet_id: ss(&io.subnet_id),
                groups: Some(vec![io.sg_id.to_string()]),
                associate_public_ip_address: io.public_ip,
                ..Default::default()
            },
        ]),
        user_data: io.user_data.as_deref().map(base64::encode),
        ..Default::default()
    };

    let res = s.ec2().run_instances(rir).await?;
    let mut ids = Vec::new();
    if let Some(insts) = &res.instances {
        for i in insts.iter() {
            ids.push(i.instance_id.as_deref().unwrap().to_string());
        }
    }

    if ids.len() != 1 {
        bail!("wanted one instance, got {:?}", ids);
    } else {
        Ok(ids[0].to_string())
    }
}

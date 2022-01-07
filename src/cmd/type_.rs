use crate::prelude::*;

pub async fn do_type(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list instance types", cmd!(do_type_ls))?;

    sel!(l).run().await
}

async fn do_type_ls(mut l: Level<Stuff>) -> Result<()> {
    l.optflag("X", "", "only 64-bit x86 instances");
    l.optflag("A", "", "only 64-bit ARM instances");
    l.optflag("C", "", "only current generation instances");
    l.optopt("n", "", "instance type name (supports wildcards)", "NAME");
    l.mutually_exclusive(&[("X", "A")]);

    l.add_column("name", 20, true);
    l.add_column("arch", 7, true);
    l.add_column("vcpu", 4, true);
    l.add_column("ram", 9, true);
    l.add_column("flags", 5, true);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let mut filters = Vec::new();
    if a.opts().opt_present("X") {
        filters.push(ec2::Filter {
            name: Some("processor-info.supported-architecture".into()),
            values: Some(vec!["x86_64".into()]),
        });
    }
    if a.opts().opt_present("A") {
        filters.push(ec2::Filter {
            name: Some("processor-info.supported-architecture".into()),
            values: Some(vec!["arm64".into()]),
        });
    }
    if a.opts().opt_present("C") {
        filters.push(ec2::Filter {
            name: Some("current-generation".into()),
            values: Some(vec!["true".into()]),
        });
    }
    if let Some(name) = a.opts().opt_str("n") {
        filters.push(ec2::Filter {
            name: Some("instance-type".into()),
            values: Some(vec![name]),
        });
    }

    let mut types = Vec::new();
    let mut tok = None;
    loop {
        let res = s
            .ec2()
            .describe_instance_types(ec2::DescribeInstanceTypesRequest {
                filters: Some(filters.clone()),
                next_token: tok,
                ..Default::default()
            })
            .await?;

        if let Some(it) = res.instance_types {
            types.extend(it);
        }

        if let Some(ntok) = res.next_token {
            tok = Some(ntok);
        } else {
            break;
        }
    }

    for typ in types {
        let mut r = Row::default();

        let arch = if let Some(pi) = &typ.processor_info {
            if let Some(arch) = &pi.supported_architectures {
                if arch.len() != 1 {
                    if arch.contains(&"i386".to_string())
                        && arch.contains(&"x86_64".to_string())
                    {
                        Some("x86".to_string())
                    } else {
                        bail!("weird instance type? {:?}", arch);
                    }
                } else if arch[0] == "x86_64_mac" {
                    Some("x86_mac".to_string())
                } else if arch[0] == "arm64" {
                    Some("arm".to_string())
                } else if arch[0] == "x86_64" {
                    Some("x86".to_string())
                } else if arch[0] == "i386" {
                    bail!("386 only? {:?}", typ.instance_type);
                } else {
                    Some(arch[0].to_string())
                }
            } else {
                None
            }
        } else {
            None
        };

        let memory_bytes = typ
            .memory_info
            .map(|mi| mi.size_in_mi_b)
            .flatten()
            .map(|megs| (megs as u64) * 1024 * 1024)
            .unwrap_or(0);

        let vcpu = typ
            .v_cpu_info
            .as_ref()
            .map(|ci| ci.default_v_cpus)
            .flatten()
            .map(|nvcpus| nvcpus as u64)
            .unwrap_or(0);

        let ena = typ
            .network_info
            .map(|ni| ni.ena_support)
            .flatten()
            .map(|ena| ena == "supported" || ena == "required");

        let flags =
            [typ.current_generation.as_flag("C"), ena.as_flag("E")].join("");

        r.add_stror("name", &typ.instance_type, "?");
        r.add_stror("arch", &arch, "-");
        r.add_bytes("ram", memory_bytes);
        r.add_u64("vcpu", vcpu);
        r.add_str("flags", &flags);

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

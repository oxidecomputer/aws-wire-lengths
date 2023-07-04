use crate::prelude::*;
use aws_sdk_ec2::types::Filter;
use futures::StreamExt;

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
        filters.push(
            Filter::builder()
                .name("processor-info.supported-architecture")
                .values("x86_64")
                .build(),
        );
    }
    if a.opts().opt_present("A") {
        filters.push(
            Filter::builder()
                .name("processor-info.supported-architecture")
                .values("arm64")
                .build(),
        );
    }
    if a.opts().opt_present("C") {
        filters.push(
            Filter::builder()
                .name("current-generation")
                .values("true")
                .build(),
        );
    }
    if let Some(name) = a.opts().opt_str("n") {
        filters
            .push(Filter::builder().name("instance-type").values(name).build());
    }

    let mut list = s
        .more()
        .ec2()
        .describe_instance_types()
        .set_filters(Some(filters.clone()))
        .into_paginator()
        .page_size(100)
        .send();

    while let Some(res) = list.next().await.transpose()? {
        for typ in res.instance_types().unwrap_or_default() {
            let mut r = Row::default();

            let arch = if let Some(pi) = typ.processor_info() {
                if let Some(arch) = pi.supported_architectures() {
                    use aws_sdk_ec2::types::ArchitectureType::*;
                    Some(
                        if arch.len() != 1 {
                            if arch.contains(&I386) && arch.contains(&X8664) {
                                "x86"
                            } else {
                                bail!("weird instance type? {:?}", arch);
                            }
                        } else {
                            match arch.get(0).unwrap() {
                                X8664 => "x86",
                                X8664Mac => "x86_mac",
                                Arm64 => "arm",
                                Arm64Mac => "arm_mac",
                                I386 => {
                                    bail!("386 only? {:?}", typ.instance_type())
                                }
                                other => {
                                    bail!("what is {:?}", other);
                                }
                            }
                        }
                        .to_string(),
                    )
                } else {
                    None
                }
            } else {
                None
            };

            let memory_bytes = typ
                .memory_info()
                .map(|mi| mi.size_in_mi_b())
                .flatten()
                .map(|megs| (megs as u64) * 1024 * 1024)
                .unwrap_or(0);

            let vcpu = typ
                .v_cpu_info()
                .map(|ci| ci.default_v_cpus())
                .flatten()
                .map(|nvcpus| nvcpus as u64)
                .unwrap_or(0);

            let ena =
                typ.network_info().map(|ni| ni.ena_support()).flatten().map(
                    |ena| {
                        matches!(
                            ena,
                            aws_sdk_ec2::types::EnaSupport::Required
                                | aws_sdk_ec2::types::EnaSupport::Supported
                        )
                    },
                );

            let flags = [typ.current_generation.as_flag("C"), ena.as_flag("E")]
                .join("");

            r.add_stror(
                "name",
                &typ.instance_type().map(|v| v.as_str().to_string()),
                "?",
            );
            r.add_stror("arch", &arch, "-");
            r.add_bytes("ram", memory_bytes);
            r.add_u64("vcpu", vcpu);
            r.add_str("flags", &flags);

            t.add_row(r);
        }
    }

    print!("{}", t.output()?);

    Ok(())
}

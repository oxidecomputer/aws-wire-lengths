use crate::prelude::*;
use aws_sdk_ec2::types::Filter;

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
    l.add_column("netperf", 16, false);
    l.add_column("bandwidth", 9, false);

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
        .ec2()
        .describe_instance_types()
        .set_filters(Some(filters.clone()))
        .into_paginator()
        .send();

    while let Some(res) = list.next().await.transpose()? {
        for typ in res.instance_types() {
            let mut r = Row::default();

            let arch = if let Some(pi) = typ.processor_info() {
                use aws_sdk_ec2::types::ArchitectureType::*;

                Some(match pi.supported_architectures() {
                    [] => bail!("no supported architectures?!"),
                    [I386, X8664] | [X8664, I386] | [X8664] | [I386] => "x86",
                    [X8664Mac] => "x86_mac",
                    [Arm64] => "arm",
                    [Arm64Mac] => "arm_mac",
                    other => bail!("what is {:?}", other),
                })
            } else {
                None
            };

            let memory_bytes = typ
                .memory_info()
                .and_then(|mi| mi.size_in_mib())
                .unwrap_or(0)
                .saturating_mul(1024 * 1024);

            let vcpu = typ
                .v_cpu_info()
                .and_then(|ci| ci.default_v_cpus())
                .unwrap_or(0);

            let mbps = typ
                .network_info()
                .and_then(|ni| ni.network_cards().get(0))
                .and_then(|nic| nic.peak_bandwidth_in_gbps())
                .map(|gbps| (gbps * 1000.0).round() as u64)
                .unwrap_or(0);

            let netperf =
                typ.network_info().and_then(|ni| ni.network_performance());

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

            r.add_stror("name", typ.instance_type().map(|v| v.as_str()), "?");
            r.add_stror("arch", arch.as_deref(), "-");
            r.add_bytes("ram", memory_bytes.try_into().unwrap());
            r.add_u64("vcpu", vcpu.try_into().unwrap());
            r.add_str("flags", &flags);
            r.add_u64("bandwidth", mbps);
            r.add_stror("netperf", netperf, "?");

            t.add_row(r);
        }
    }

    print!("{}", t.output()?);

    Ok(())
}

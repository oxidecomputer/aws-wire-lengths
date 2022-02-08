use crate::prelude::*;

pub async fn do_route(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list route tables", cmd!(list))?;
    l.cmd("show", "show the contents of a route table", cmd!(show))?;
    l.cmd("dump", "dump raw detail about a route table", cmd!(dump))?;
    l.cmd("for", "find the route table for a resource", cmd!(find))?;
    l.cmd("create", "create a route table", cmd!(table_create))?;
    l.cmd("destroy", "destroy a route table", cmd!(table_destroy))?;
    l.cmd("add", "add a route", cmd!(route_create))?;
    l.cmd("delete", "remove a route", cmd!(route_delete))?;
    l.cmd(
        "associate",
        "associate a subnet with a route table",
        cmd!(associate),
    )?;

    sel!(l).run().await
}

async fn table_create(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME"));

    l.reqopt("V", "vpc", "VPC name or ID for subnet creation", "VPC");

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the name for the route table");
    }
    let name = a.args().get(0).unwrap().to_string();

    let vpc = get_vpc_fuzzy(s, &a.opts().opt_str("vpc").unwrap()).await?;

    let tag_specifications = Some(vec![ec2::TagSpecification {
        resource_type: ss("route-table"),
        tags: Some(vec![ec2::Tag {
            key: ss("Name"),
            value: Some(name),
        }]),
    }]);

    let res = s
        .ec2()
        .create_route_table(ec2::CreateRouteTableRequest {
            tag_specifications,
            vpc_id: vpc.vpc_id.unwrap(),
            ..Default::default()
        })
        .await?;

    println!("{}", res.route_table.unwrap().route_table_id.unwrap());
    Ok(())
}

async fn table_destroy(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("RTB-ID|NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the name of the route table to destroy");
    }
    let name = a.args().get(0).unwrap().to_string();

    let rt = get_rt_fuzzy(s, &name, true).await?;

    s.ec2()
        .delete_route_table(ec2::DeleteRouteTableRequest {
            route_table_id: rt.route_table_id.unwrap().to_string(),
            ..Default::default()
        })
        .await?;

    Ok(())
}

async fn route_create(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("RTB-ID|NAME DESTINATION TYPE [TARGET DETAILS...]"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() < 3 {
        bad_args!(l, "specify route table, destination CIDR, and type");
    }

    let rt = get_rt_fuzzy(s, a.args().get(0).unwrap(), true).await?;
    let cidr = a.args().get(1).unwrap().to_string();

    let target = match a.args().get(2).as_ref().unwrap().as_str() {
        "instance" => {
            if a.args().len() < 4 {
                bad_args!(l, "specify instance ID");
            }

            let inst = get_instance_fuzzy(s, a.args().get(3).unwrap()).await?;
            if inst.nics.len() != 1 {
                bail!(
                    "instance {} has {} NICs, not 1",
                    inst.id,
                    inst.nics.len()
                );
            }

            Target::Instance {
                id: inst.id,
                nic: inst.nics[0].to_string(),
            }
        }
        "internet" | "igw" | "gateway" => {
            if a.args().len() < 4 {
                bad_args!(l, "specify Internet gateway name or ID");
            }

            let igw = get_igw_fuzzy(s, a.args().get(3).unwrap()).await?;

            Target::Internet {
                id: igw.internet_gateway_id().unwrap().to_string(),
            }
        }
        "nat" => {
            if a.args().len() < 4 {
                bad_args!(l, "specify NAT gateway name or ID");
            }

            let nat = get_nat_fuzzy(s, a.args().get(3).unwrap()).await?;

            Target::Nat {
                id: nat.nat_gateway_id().unwrap().to_string(),
            }
        }
        x => bail!("cannot make routes for {:?} targets yet", x),
    };

    let res =
        s.ec2()
            .create_route(target.to_create(
                &cidr,
                rt.route_table_id.as_ref().unwrap().as_str(),
            )?)
            .await?;
    assert!(res.return_.unwrap());

    Ok(())
}

async fn route_delete(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("RTB-ID|NAME DESTINATION"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify route table and destination CIDR address");
    }

    let rt = get_rt_fuzzy(s, a.args().get(0).unwrap(), true).await?;

    s.ec2()
        .delete_route(ec2::DeleteRouteRequest {
            route_table_id: rt.route_table_id.unwrap(),
            destination_cidr_block: Some(a.args().get(1).unwrap().to_string()),
            ..Default::default()
        })
        .await?;

    Ok(())
}

async fn find(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME|VPC-ID|SUBNET-ID"));
    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify target resource");
    }

    let rt = get_rt_fuzzy(s, a.args().get(0).unwrap(), false).await?;

    println!("{}", rt.route_table_id.unwrap());
    Ok(())
}

async fn list(mut l: Level<Stuff>) -> Result<()> {
    l.optopt("V", "vpc", "filter instances by VPC name or ID", "VPC");

    l.add_column("id", 24, true);
    l.add_column("name", 24, true);

    let a = no_args!(l);
    let s = l.context();
    let mut t = a.table();

    let filters = filter_vpc_fuzzy(s, a.opts().opt_str("vpc")).await?;

    let res = s
        .ec2()
        .describe_route_tables(ec2::DescribeRouteTablesRequest {
            filters,
            ..Default::default()
        })
        .await?;

    for rt in res.route_tables.unwrap_or_default().iter() {
        let n = rt.tags.tag("Name");

        let mut r = Row::default();
        r.add_stror("id", &rt.route_table_id, "?");
        r.add_stror("name", &n, "-");
        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

#[derive(Debug)]
enum Target {
    #[allow(dead_code)]
    Instance {
        id: String,
        nic: String,
    },
    Local,
    Nat {
        id: String,
    },
    Internet {
        id: String,
    },
    Peering {
        id: String,
    },
}

impl Target {
    fn type_column(&self) -> &'static str {
        match self {
            Target::Instance { .. } => "instance",
            Target::Local => "local",
            Target::Nat { .. } => "nat",
            Target::Internet { .. } => "internet",
            Target::Peering { .. } => "peering",
        }
    }

    fn info(&self) -> String {
        match self {
            Target::Instance { id, .. } => id.to_string(),
            Target::Local => "-".to_string(),
            Target::Nat { id } => id.to_string(),
            Target::Internet { id } => id.to_string(),
            Target::Peering { id } => id.to_string(),
        }
    }

    fn to_create(
        &self,
        cidr: &str,
        rtb: &str,
    ) -> Result<ec2::CreateRouteRequest> {
        let route_table_id = rtb.to_string();
        let destination_cidr_block = Some(cidr.to_string());

        match self {
            Target::Instance { id, .. } => Ok(ec2::CreateRouteRequest {
                route_table_id,
                destination_cidr_block,
                instance_id: Some(id.to_string()),
                //network_interface_id: Some(nic.to_string()),
                ..Default::default()
            }),
            Target::Internet { id } => Ok(ec2::CreateRouteRequest {
                route_table_id,
                destination_cidr_block,
                gateway_id: Some(id.to_string()),
                ..Default::default()
            }),
            Target::Nat { id } => Ok(ec2::CreateRouteRequest {
                route_table_id,
                destination_cidr_block,
                nat_gateway_id: Some(id.to_string()),
                ..Default::default()
            }),
            other => bail!("cannot yet make a route for {:?}", other),
        }
    }
}

trait RouteExt {
    fn target(&self) -> Result<Target>;
}

impl RouteExt for ec2::Route {
    fn target(&self) -> Result<Target> {
        if let Some(iid) = &self.instance_id {
            if let Some(nid) = &self.network_interface_id {
                return Ok(Target::Instance {
                    id: iid.to_string(),
                    nic: nid.to_string(),
                });
            } else {
                bail!("instance ID without network interface ID: {:?}", self);
            }
        }
        if self.network_interface_id.is_some() {
            bail!("network interface ID without instance ID: {:?}", self);
        }

        if let Some(gw) = &self.gateway_id {
            if gw == "local" {
                return Ok(Target::Local);
            }

            if gw.starts_with("igw-") {
                return Ok(Target::Internet { id: gw.to_string() });
            }

            bail!("unknown gateway type: {:?}", self);
        }

        if let Some(nat) = &self.nat_gateway_id {
            return Ok(Target::Nat {
                id: nat.to_string(),
            });
        }

        if let Some(pcx) = &self.vpc_peering_connection_id {
            return Ok(Target::Peering {
                id: pcx.to_string(),
            });
        }

        bail!("unknown route type: {:?}", self);
    }
}

async fn dump(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("RTB-ID|NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the route table to dump");
    }

    let rtable = get_rt_fuzzy(s, a.args().get(0).unwrap(), true).await?;

    println!("{:#?}", rtable);
    Ok(())
}

async fn show(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("TABLE"));

    l.add_column("destination", 18, true);
    l.add_column("flags", 5, true);
    l.add_column("type", 10, true);
    l.add_column("target", 20, true);
    l.add_column("state", 9, false);

    let a = args!(l);
    let s = l.context();
    let mut t = a.table();

    if a.args().len() != 1 {
        bad_args!(l, "specify the route table to show");
    }

    let rtable = get_rt_fuzzy(s, a.args().get(0).unwrap(), true).await?;

    let empty = Vec::new();
    let routes = rtable.routes.as_ref().unwrap_or(&empty);

    for rt in routes.iter() {
        let target = rt.target()?;

        let active = rt.state.as_deref().unwrap_or_default() == "active";
        let blackhole = rt.state.as_deref().unwrap_or_default() == "blackhole";
        let flags = [active.as_flag("A"), blackhole.as_flag("B")].join("");

        let mut r = Row::default();

        if let Some(cidr) = rt.destination_cidr_block.as_deref() {
            r.add_str("destination", cidr);
        } else {
            eprintln!("WARNING: only basic IPv4 destinations supported");
            continue;
        }

        r.add_stror("state", &rt.state, "?");
        r.add_str("target", &target.info());
        r.add_str("type", target.type_column());
        r.add_str("flags", &flags);

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

fn find_association(
    drto: aws_sdk_ec2::output::DescribeRouteTablesOutput,
    subnet_id: &str,
) -> Option<String> {
    if let Some(rtables) = drto.route_tables {
        for rt in rtables {
            if let Some(assocs) = rt.associations {
                for a in assocs {
                    if a.subnet_id() == Some(subnet_id) {
                        /*
                         * XXX Should we check the association state?
                         */
                        return Some(
                            a.route_table_association_id().unwrap().to_string(),
                        );
                    }
                }
            }
        }
    }

    None
}

async fn associate(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("RTB-ID|NAME SUBNET-ID|NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify the route table and the subnet");
    }

    /*
     * This is the target route table and the subnet we want to attach.
     */
    let rtb = get_rt_fuzzy(s, a.args().get(0).unwrap().as_str(), true).await?;
    let net = get_subnet_fuzzy(s, a.args().get(1).unwrap().as_str()).await?;
    let id = net.subnet_id().unwrap();

    /*
     * Because AWS is atrocious, there is no "just associate this subnet with
     * this route table please" request.  Instead, we must rifle around in our
     * drawers looking for an existing association and try to replace it, and if
     * there is not one we need to create a new one.
     *
     * Look for an existing association ID for this subnet:
     */
    let direct = s
        .more()
        .ec2()
        .describe_route_tables()
        .filters(
            aws_sdk_ec2::model::Filter::builder()
                .name("vpc-id")
                .values(net.vpc_id().unwrap())
                .build(),
        )
        .filters(
            aws_sdk_ec2::model::Filter::builder()
                .name("association.subnet-id")
                .values(net.subnet_id().unwrap())
                .build(),
        )
        .send()
        .await?;

    if let Some(assoc) = find_association(direct, id) {
        eprintln!("found existing association ID {}", assoc);

        let res = s
            .more()
            .ec2()
            .replace_route_table_association()
            .association_id(assoc)
            .route_table_id(rtb.route_table_id.unwrap())
            .send()
            .await?;
        println!("{:?}", res);
    } else {
        eprintln!("no existing association ID found");

        let res = s
            .more()
            .ec2()
            .associate_route_table()
            .subnet_id(id)
            .route_table_id(rtb.route_table_id.unwrap())
            .send()
            .await?;
        println!("{:?}", res);
    }

    Ok(())
}

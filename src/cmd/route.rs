use crate::prelude::*;

pub async fn do_route(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list routing tables", cmd!(list))?;
    l.cmd("show", "show the contents of a routing table", cmd!(show))?;
    l.cmd("for", "find the routing table for a resource", cmd!(find))?;
    l.cmda("delete", "rm", "remove a route", cmd!(delete))?;

    sel!(l).run().await
}

async fn delete(mut l: Level<Stuff>) -> Result<()> {
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

enum Target {
    Instance { id: String, nic: String },
    Local,
    Nat { id: String },
    Internet { id: String },
    Peering { id: String },
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
        bad_args!(l, "specify the routing table to show");
    }

    let rtable = get_rt_fuzzy(s, a.args().get(0).unwrap(), true).await?;

    let empty = Vec::new();
    let routes = rtable.routes.as_ref().unwrap_or_else(|| &empty);

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

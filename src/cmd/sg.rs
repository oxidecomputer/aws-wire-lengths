use crate::prelude::*;
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
};

#[derive(Clone, PartialEq, Eq)]
enum RuleTarget {
    Ipv4Any,
    Ipv4(String),
    Ipv6Any,
    Ipv6(String),
    ThisGroup,
    OtherGroup(String),
}

#[derive(Clone, PartialEq, Eq)]
enum RuleDirection {
    In,
    Out,
}

#[derive(Clone, PartialEq, Eq)]
enum RuleProtocol {
    Any,
    Udp,
    Tcp,
    Icmp,
    Icmp6,
}

#[derive(Clone, PartialEq, Eq)]
struct Rule {
    dir: RuleDirection,
    target: RuleTarget,
    proto: RuleProtocol,
    port_from: Option<u32>,
    port_to: Option<u32>,
    description: Option<String>,
}

impl Rule {
    fn to_ip_permission(&self, sgid: &str) -> aws_sdk_ec2::model::IpPermission {
        let mut b = aws_sdk_ec2::model::IpPermission::builder();

        b = match &self.target {
            RuleTarget::Ipv4Any => b.ip_ranges(
                aws_sdk_ec2::model::IpRange::builder()
                    .cidr_ip("0.0.0.0/0")
                    .set_description(self.description.clone())
                    .build(),
            ),
            RuleTarget::Ipv4(cidr) => b.ip_ranges(
                aws_sdk_ec2::model::IpRange::builder().cidr_ip(cidr).build(),
            ),
            RuleTarget::Ipv6Any => b.ipv6_ranges(
                aws_sdk_ec2::model::Ipv6Range::builder()
                    .cidr_ipv6("0::0/0")
                    .set_description(self.description.clone())
                    .build(),
            ),
            RuleTarget::Ipv6(cidr) => b.ipv6_ranges(
                aws_sdk_ec2::model::Ipv6Range::builder()
                    .cidr_ipv6(cidr)
                    .set_description(self.description.clone())
                    .build(),
            ),
            RuleTarget::ThisGroup => b.user_id_group_pairs(
                aws_sdk_ec2::model::UserIdGroupPair::builder()
                    .group_id(sgid)
                    .set_description(self.description.clone())
                    .build(),
            ),
            RuleTarget::OtherGroup(other) => b.user_id_group_pairs(
                aws_sdk_ec2::model::UserIdGroupPair::builder()
                    .group_id(other)
                    .set_description(self.description.clone())
                    .build(),
            ),
        };

        b = match &self.proto {
            RuleProtocol::Any => b.ip_protocol("-1"),
            RuleProtocol::Udp => b.ip_protocol("udp"),
            RuleProtocol::Tcp => b.ip_protocol("tcp"),
            RuleProtocol::Icmp => b.ip_protocol("icmp"),
            RuleProtocol::Icmp6 => b.ip_protocol("icmp6"),
        };

        b = if let Some(port) = self.port_from {
            b.from_port(port.try_into().unwrap())
        } else {
            b.from_port(-1)
        };

        b = if let Some(port) = self.port_to {
            b.to_port(port.try_into().unwrap())
        } else {
            b.to_port(-1)
        };

        b.build()
    }

    fn info(&self) -> String {
        let mut out = Vec::new();

        out.push(
            match self.dir {
                RuleDirection::In => "in from",
                RuleDirection::Out => "out to",
            }
            .to_string(),
        );

        out.push(match &self.target {
            RuleTarget::Ipv4Any => "inet any".to_string(),
            RuleTarget::Ipv4(cidr) => format!("inet {}", cidr),
            RuleTarget::Ipv6Any => "inet6 any".to_string(),
            RuleTarget::Ipv6(cidr) => format!("inet6 {}", cidr),
            RuleTarget::ThisGroup => "group self".to_string(),
            RuleTarget::OtherGroup(gr) => format!("group {}", gr),
        });

        out.push(
            match &self.proto {
                RuleProtocol::Any => "proto any",
                RuleProtocol::Udp => "proto udp",
                RuleProtocol::Tcp => "proto tcp",
                RuleProtocol::Icmp => "proto icmp",
                RuleProtocol::Icmp6 => "proto icmp6",
            }
            .to_string(),
        );

        out.push(match (self.port_from, self.port_to) {
            (Some(f), None) => format!("port {}", f),
            (Some(f), Some(t)) if f == t => format!("port {}", f),
            (Some(f), Some(t)) => format!("port {}-{}", f, t),
            (None, _) => "port any".to_string(),
        });

        if let Some(desc) = &self.description {
            out.push(format!("# {}", desc));
        }

        out.join(" ")
    }
}

impl TryFrom<&str> for Rule {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut words = value.split_whitespace();

        let dir = match words.next() {
            Some("in") => {
                if let Some("from") = words.next() {
                    RuleDirection::In
                } else {
                    bail!("expected \"from\"");
                }
            }
            Some("out") => {
                if let Some("to") = words.next() {
                    RuleDirection::Out
                } else {
                    bail!("expected \"to\"");
                }
            }
            other => bail!("expected in or out, got {:?}", other),
        };

        let target = match (words.next(), words.next()) {
            (Some("group"), Some("self")) => RuleTarget::ThisGroup,
            (Some("group"), Some(gr)) => RuleTarget::OtherGroup(gr.to_string()),
            (Some("inet"), Some("any")) => RuleTarget::Ipv4Any,
            (Some("inet"), Some(cidr)) => RuleTarget::Ipv4(cidr.to_string()),
            (Some("inet6"), Some("any")) => RuleTarget::Ipv6Any,
            (Some("inet6"), Some(cidr)) => RuleTarget::Ipv6(cidr.to_string()),
            other => {
                bail!("expect group/inet/inet6, found {:?}", other);
            }
        };

        match words.next() {
            Some("proto") => {}
            other => bail!("expected \"proto\", not {:?}", other),
        }
        let proto = match words.next() {
            Some("any") => RuleProtocol::Any,
            Some("tcp") => RuleProtocol::Tcp,
            Some("udp") => RuleProtocol::Udp,
            Some("icmp") => RuleProtocol::Icmp,
            Some("icmp6") => RuleProtocol::Icmp6,
            other => bail!("invalid protocol {:?}", other),
        };

        match words.next() {
            Some("port") => {}
            other => bail!("expected \"port\", not {:?}", other),
        }
        let (port_from, port_to) = if let Some(spec) = words.next() {
            if spec == "any" {
                (None, None)
            } else if let Some((f, t)) = spec.split_once('-') {
                /*
                 * A port range!
                 */
                let f = f.parse::<u32>()?;
                let t = t.parse::<u32>()?;
                if f > t {
                    (Some(t), Some(f))
                } else {
                    (Some(f), Some(t))
                }
            } else {
                /*
                 * Just one port number.
                 */
                let f = spec.parse::<u32>()?;
                (Some(f), Some(f))
            }
        } else {
            bail!("expected a port range specification");
        };

        let description = match words.next() {
            Some("#") => Some(
                words.map(str::to_string).collect::<Vec<String>>().join(" "),
            ),
            Some(other) => bail!("unexpected {:?}", other),
            None => None,
        };

        Ok(Rule {
            dir,
            target,
            proto,
            port_from,
            port_to,
            description,
        })
    }
}

trait TheirRuleExt {
    fn to_rule(&self) -> Result<Rule>;
    fn target(&self) -> Result<RuleTarget>;
}

impl TheirRuleExt for aws_sdk_ec2::model::SecurityGroupRule {
    fn to_rule(&self) -> Result<Rule> {
        Ok(Rule {
            dir: match self.is_egress() {
                Some(true) => RuleDirection::Out,
                Some(false) => RuleDirection::In,
                None => bail!("missing is_egress? {:?}", self),
            },
            target: self.target()?,
            proto: match self.ip_protocol.as_deref() {
                Some("-1") => RuleProtocol::Any,
                Some("tcp") => RuleProtocol::Tcp,
                Some("udp") => RuleProtocol::Udp,
                Some("icmp") => RuleProtocol::Icmp,
                Some("icmp6") => RuleProtocol::Icmp6,
                other => bail!("bad protocol {:?} for {:?}", other, self),
            },
            port_from: match self.from_port {
                Some(-1) => None,
                Some(port) if port >= 0 => Some(port as u32),
                other => bail!("invalid to port {:?} for {:?}", other, self),
            },
            port_to: match self.from_port {
                Some(-1) => None,
                Some(port) if port >= 0 => Some(port as u32),
                other => bail!("invalid from port {:?} for {:?}", other, self),
            },
            description: self.description.clone(),
        })
    }

    fn target(&self) -> Result<RuleTarget> {
        if let Some(cidr) = self.cidr_ipv4() {
            if self.cidr_ipv6().is_some()
                || self.referenced_group_info().is_some()
            {
                bail!("conflicting target for {:?}", self);
            }
            if cidr == "0.0.0.0/0" {
                Ok(RuleTarget::Ipv4Any)
            } else {
                Ok(RuleTarget::Ipv4(cidr.to_string()))
            }
        } else if let Some(cidr) = self.cidr_ipv6() {
            if self.cidr_ipv4().is_some()
                || self.referenced_group_info().is_some()
            {
                bail!("conflicting target for {:?}", self);
            }
            if cidr == "::/0" {
                Ok(RuleTarget::Ipv6Any)
            } else {
                Ok(RuleTarget::Ipv6(cidr.to_string()))
            }
        } else if let Some(refgr) = self.referenced_group_info() {
            if self.cidr_ipv4().is_some() || self.cidr_ipv6().is_some() {
                bail!("conflicting target for {:?}", self);
            }
            if let Some(gr) = refgr.group_id() {
                if gr == self.group_id().as_deref().unwrap() {
                    Ok(RuleTarget::ThisGroup)
                } else {
                    Ok(RuleTarget::OtherGroup(gr.to_string()))
                }
            } else {
                bail!("missing referenced group ID for {:?}", self);
            }
        } else {
            bail!("unknown target type for {:?}", self);
        }
    }
}

pub async fn do_sg(mut l: Level<Stuff>) -> Result<()> {
    l.cmda("list", "ls", "list security groups", cmd!(do_sg_ls))?;
    l.cmd("create", "create a security group", cmd!(create))?;
    l.cmd("destroy", "destroy a security group", cmd!(destroy))?;
    l.cmd(
        "apply",
        "apply a rule file to an existing group",
        cmd!(apply),
    )?;
    l.cmd("dump", "raw dump of a security group", cmd!(dump))?;
    l.cmd("show", "list rules from a security group", cmd!(show))?;

    sel!(l).run().await
}

async fn do_sg_ls(mut l: Level<Stuff>) -> Result<()> {
    l.optopt("V", "vpc", "filter instances by VPC name or ID", "VPC");

    l.add_column("id", 20, true);
    l.add_column("name", 28, true);
    l.add_column("vpc", WIDTH_VPC, true);
    l.add_column("desc", 32, false);
    l.add_column("fulldesc", 50, false);

    let a = no_args!(l);
    let mut t = a.table();
    let s = l.context();

    let filters = filter_vpc_fuzzy(s, a.opts().opt_str("vpc")).await?;

    let res = s
        .ec2()
        .describe_security_groups(ec2::DescribeSecurityGroupsRequest {
            filters,
            ..Default::default()
        })
        .await?;

    let x = Vec::new();
    for sg in res.security_groups.as_ref().unwrap_or(&x) {
        let mut r = Row::default();

        r.add_stror("id", &sg.group_id, "?");
        r.add_stror("name", &sg.group_name, "-");
        r.add_stror("vpc", &sg.vpc_id, "-");
        let desc = if let Some(desc) = sg.description.as_deref() {
            if let Some(name) = sg.group_name.as_deref() {
                desc.trim_start_matches(name)
            } else {
                desc
            }
            .trim()
        } else {
            "-"
        };
        r.add_str("desc", desc);
        r.add_stror("fulldesc", &sg.description, "-");

        t.add_row(r);
    }

    print!("{}", t.output()?);

    Ok(())
}

async fn create(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME DESCRIPTION"));

    l.reqopt("V", "vpc", "create security group in this VPC", "VPC");

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 2 {
        bad_args!(l, "specify the security group name and description");
    }

    let name = a.args().get(0).unwrap().to_string();
    let desc = a.args().get(1).unwrap().to_string();
    let vpc = get_vpc_fuzzy(s, &a.opts().opt_str("vpc").unwrap()).await?;

    let res = s
        .more()
        .ec2()
        .create_security_group()
        .group_name(name)
        .description(desc)
        .vpc_id(vpc.vpc_id.unwrap())
        .send()
        .await?;

    println!("{}", res.group_id().unwrap());
    Ok(())
}

async fn destroy(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME"));

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the security group name to delete");
    }

    let sg = get_sg_fuzzy(s, &a.args().get(0).unwrap()).await?;

    s.more()
        .ec2()
        .delete_security_group()
        .group_id(sg.group_id.unwrap())
        .send()
        .await?;

    Ok(())
}

async fn apply(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("NAME"));

    l.reqopt("f", "file", "rule file to use as template", "PATH");

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the security group name");
    }

    let sg = get_sg_fuzzy(s, &a.args().get(0).unwrap()).await?;
    let id = sg.group_id.as_deref().unwrap().to_string();

    /*
     * Parse the rule file.
     */
    let template = {
        let mut f = std::fs::File::open(a.opts().opt_str("file").unwrap())?;
        let mut s = String::new();
        f.read_to_string(&mut s)?;
        s.lines()
            .map(|l| Rule::try_from(l))
            .collect::<Result<Vec<_>>>()?
    };

    /*
     * Get the list of existing rules and turn them into our parsed format.
     */
    let res = s
        .more()
        .ec2()
        .describe_security_group_rules()
        .filters(
            aws_sdk_ec2::model::Filter::builder()
                .name("group-id")
                .values(&id)
                .build(),
        )
        .max_results(1000)
        .send()
        .await?;

    let existing = res
        .security_group_rules()
        .unwrap_or_default()
        .iter()
        .map(|sgr| {
            Ok((
                sgr.security_group_rule_id().unwrap().to_string(),
                sgr.to_rule()?,
            ))
        })
        .collect::<Result<HashMap<String, Rule>>>()?;

    /*
     * For each local rule, check to make sure there is a matching remote rule.
     */
    let mut used = HashSet::new();
    let mut to_create = Vec::new();
    for local in template.iter() {
        let remotes = existing
            .iter()
            .filter_map(|(ruleid, remote)| {
                if local == remote {
                    Some(ruleid.to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        match remotes.len() {
            0 => {
                println!("+ {}", local.info());
                to_create.push(local.clone());
            }
            1 => {
                if !used.insert(remotes[0].clone()) {
                    bail!(
                        "remote rule already matched? {}: {}",
                        remotes[0],
                        local.info()
                    );
                }
                println!("  {}", local.info());
            }
            _ => {
                bail!(
                    "too many matches {:?} for rule: {}",
                    remotes,
                    local.info()
                );
            }
        }
    }

    /*
     * For each remote rule, check to ensure it matches a rule in the template.
     * If it does not, we must remove it.
     */
    for (ruleid, remote) in existing.iter() {
        if used.contains(ruleid) {
            continue;
        }

        println!("- {}", remote.info());
        match &remote.dir {
            RuleDirection::In => {
                s.more()
                    .ec2()
                    .revoke_security_group_ingress()
                    .group_id(&id)
                    .security_group_rule_ids(ruleid)
                    .send()
                    .await?;
            }
            RuleDirection::Out => {
                s.more()
                    .ec2()
                    .revoke_security_group_egress()
                    .group_id(&id)
                    .security_group_rule_ids(ruleid)
                    .send()
                    .await?;
            }
        }
    }

    for rule in to_create {
        match &rule.dir {
            RuleDirection::In => {
                s.more()
                    .ec2()
                    .authorize_security_group_ingress()
                    .group_id(&id)
                    .ip_permissions(rule.to_ip_permission(&id))
                    .send()
                    .await?;
            }
            RuleDirection::Out => {
                s.more()
                    .ec2()
                    .authorize_security_group_egress()
                    .group_id(&id)
                    .ip_permissions(rule.to_ip_permission(&id))
                    .send()
                    .await?;
            }
        }
    }

    Ok(())
}

async fn show(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("SG-ID"));

    let a = args!(l);
    let s = l.context();
    let c = s.more().ec2();

    if a.args().len() != 1 {
        bad_args!(l, "specify the security group to show");
    }

    let sg = get_sg_fuzzy(s, a.args().get(0).unwrap()).await?;
    let id = sg.group_id.as_deref().unwrap();

    eprintln!("security group {}:", id);

    let res = c
        .describe_security_group_rules()
        .filters(
            aws_sdk_ec2::model::Filter::builder()
                .name("group-id")
                .values(id)
                .build(),
        )
        .max_results(1000)
        .send()
        .await?;

    for egress in [false, true] {
        for rule in res.security_group_rules().unwrap_or_default() {
            if rule.is_egress.unwrap_or_default() != egress {
                continue;
            }

            println!("{}", rule.to_rule()?.info());
        }
    }

    Ok(())
}

async fn dump(mut l: Level<Stuff>) -> Result<()> {
    l.usage_args(Some("SG-ID"));

    l.optopt("V", "vpc", "filter instances by VPC name or ID", "VPC");

    let a = args!(l);
    let s = l.context();

    if a.args().len() != 1 {
        bad_args!(l, "specify the security group to show");
    }

    let sg = get_sg_fuzzy(s, a.args().get(0).unwrap()).await?;

    println!("{:#?}", sg);

    Ok(())
}

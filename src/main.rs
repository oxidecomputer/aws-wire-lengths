/*
 * Copyright 2023 Oxide Computer Company
 */

#![allow(clippy::many_single_char_names)]

use anyhow::{anyhow, Result};
use aws_types::region::Region;
use hiercmd::prelude::*;

mod base;
mod body;
mod util;

mod prelude {
    pub(crate) use std::collections::HashMap;
    pub(crate) use std::fs::File;
    pub(crate) use std::io::{Read, Write};
    pub(crate) use std::os::unix::fs::DirBuilderExt;
    pub(crate) use std::os::unix::prelude::*;
    pub(crate) use std::time::Duration;

    #[allow(unused_imports)]
    pub(crate) use anyhow::{anyhow, bail, Context, Result};
    pub(crate) use hiercmd::prelude::*;
    pub(crate) use rand::thread_rng;
    pub(crate) use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    pub(crate) use rsa::traits::PublicKeyParts;

    pub(crate) use super::base::*;
    pub(crate) use super::body::StreamBody;
    pub(crate) use super::util::*;
    pub(crate) use super::Stuff;
}

mod cmd;
use cmd::az::do_az;
use cmd::config::do_config;
use cmd::gateway::do_gateway;
use cmd::image::{ami_from_file, do_image};
use cmd::instance::do_instance;
use cmd::interface::do_if;
use cmd::ip::do_ip;
use cmd::key::do_key;
use cmd::nat::do_nat;
use cmd::role::do_role;
use cmd::route::do_route;
use cmd::s3::do_s3;
use cmd::sg::do_sg;
use cmd::snapshot::do_snapshot;
use cmd::subnet::do_subnet;
use cmd::type_::do_type;
use cmd::volume::do_volume;
use cmd::vpc::do_vpc;

#[derive(Default)]
pub struct Stuff {
    region_ec2: Option<Region>,
    region_s3: Option<Region>,
    region_sts: Option<Region>,

    ec2: Option<aws_sdk_ec2::Client>,
    ebs: Option<aws_sdk_ebs::Client>,
    s3: Option<aws_sdk_s3::Client>,
    sts: Option<aws_sdk_sts::Client>,
    ec2ic: Option<aws_sdk_ec2instanceconnect::Client>,
}

#[allow(dead_code)]
impl Stuff {
    fn aws_config_loader() -> aws_config::ConfigLoader {
        aws_config::defaults(aws_config::BehaviorVersion::v2023_11_09())
    }

    fn region_ec2(&self) -> &Region {
        self.region_ec2.as_ref().unwrap()
    }

    fn region_s3(&self) -> &Region {
        self.region_s3.as_ref().unwrap()
    }

    fn region_sts(&self) -> &Region {
        self.region_sts.as_ref().unwrap()
    }

    pub fn ec2(&self) -> &aws_sdk_ec2::Client {
        self.ec2.as_ref().unwrap()
    }

    pub fn ebs(&self) -> &aws_sdk_ebs::Client {
        self.ebs.as_ref().unwrap()
    }

    pub async fn ec2_for_region(&self, region: &str) -> aws_sdk_ec2::Client {
        let cfg = Self::aws_config_loader()
            .region(Region::new(region.to_string()))
            .load()
            .await;
        aws_sdk_ec2::Client::new(&cfg)
    }

    pub fn s3(&self) -> &aws_sdk_s3::Client {
        self.s3.as_ref().unwrap()
    }

    pub fn sts(&self) -> &aws_sdk_sts::Client {
        self.sts.as_ref().unwrap()
    }

    pub fn ic(&self) -> &aws_sdk_ec2instanceconnect::Client {
        self.ec2ic.as_ref().unwrap()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut l = Level::new("aws-wire-lengths", Stuff::default());

    l.optopt("r", "region-ec2", "region for EC2", "REGION");
    l.optopt("R", "region-s3", "region for S3", "REGION");
    l.optopt("", "region-sts", "region for STS", "REGION");

    l.cmda("instance", "inst", "instance management", cmd!(do_instance))?;
    l.cmda("volume", "vol", "volume management", cmd!(do_volume))?;
    l.cmda("snapshot", "snap", "snapshot management", cmd!(do_snapshot))?;
    l.cmda("image", "ami", "image (AMI) management", cmd!(do_image))?;
    l.cmd(
        "role",
        "security token service (STS) management",
        cmd!(do_role),
    )?;
    l.cmd("sg", "security group management", cmd!(do_sg))?;
    l.cmd("key", "SSH key management", cmd!(do_key))?;
    l.cmd("vpc", "VPC management", cmd!(do_vpc))?;
    l.cmd("subnet", "subnet management", cmd!(do_subnet))?;
    l.cmda(
        "gateway",
        "igw",
        "Internet gateway management",
        cmd!(do_gateway),
    )?;
    l.cmd("nat", "managed NAT gateway management", cmd!(do_nat))?;
    l.cmda("route", "rt", "routing table management", cmd!(do_route))?;
    l.cmd("ip", "elastic IP address management", cmd!(do_ip))?;
    l.cmda(
        "interface",
        "if",
        "network interface management",
        cmd!(do_if),
    )?;
    l.cmd(
        "config",
        "manage account- or region-level configuration",
        cmd!(do_config),
    )?;
    l.cmd("type", "instance type management", cmd!(do_type))?;
    l.cmd("az", "availability zone management", cmd!(do_az))?;
    l.cmda("s3", "s", "S3 object storage", cmd!(do_s3))?;
    /*
     * XXX These are used in some scripts, so leave them (but hidden) for now.
     */
    l.hcmd(
        "ami-from-file",
        "COMPAT: AMI from file",
        cmd!(ami_from_file),
    )?;
    l.hcmd("everything", "COMPAT: AMI from file", cmd!(ami_from_file))?;

    /*
     * Parse arguments and select which command we will be running.
     */
    let mut s = sel!(l);

    s.context_mut().region_ec2 = Some(
        aws_config::meta::region::RegionProviderChain::first_try(
            s.opts().opt_str("region-ec2").map(|s| Region::new(s)),
        )
        .or_default_provider()
        .or_else(Region::new("us-east-1"))
        .region()
        .await
        .ok_or_else(|| anyhow!("could not get region for EC2"))?,
    );
    s.context_mut().region_s3 = Some(
        aws_config::meta::region::RegionProviderChain::first_try(
            s.opts().opt_str("region-s3").map(|s| Region::new(s)),
        )
        .or_default_provider()
        .or_else(Region::new("us-east-1"))
        .region()
        .await
        .ok_or_else(|| anyhow!("could not get region for EC2"))?,
    );
    s.context_mut().region_sts = Some(
        aws_config::meta::region::RegionProviderChain::first_try(
            s.opts().opt_str("region-sts").map(|s| Region::new(s)),
        )
        .or_default_provider()
        .or_else(Region::new("us-east-1"))
        .region()
        .await
        .ok_or_else(|| anyhow!("could not get region for EC2"))?,
    );

    let cfg = Stuff::aws_config_loader()
        .region(s.context().region_ec2().clone())
        .load()
        .await;
    s.context_mut().ec2 = Some(aws_sdk_ec2::Client::new(&cfg));

    let cfg = Stuff::aws_config_loader()
        .region(s.context().region_ec2().clone())
        .load()
        .await;
    s.context_mut().ec2ic = Some(aws_sdk_ec2instanceconnect::Client::new(&cfg));

    let cfg = Stuff::aws_config_loader()
        .region(s.context().region_ec2().clone())
        .load()
        .await;
    s.context_mut().ebs = Some(aws_sdk_ebs::Client::new(&cfg));

    let cfg = Stuff::aws_config_loader()
        .region(s.context().region_s3().clone())
        .load()
        .await;
    s.context_mut().s3 = Some(aws_sdk_s3::Client::new(&cfg));

    let cfg = Stuff::aws_config_loader()
        .region(s.context().region_sts().clone())
        .load()
        .await;
    s.context_mut().sts = Some(aws_sdk_sts::Client::new(&cfg));

    s.run().await
}

/*
 * Copyright 2021 Oxide Computer Company
 */

#![allow(clippy::many_single_char_names)]

use std::str::FromStr;

use anyhow::{Context, Result};
use hiercmd::prelude::*;
use rusoto_core::{HttpClient, Region};
use rusoto_credential::{
    DefaultCredentialsProvider, EnvironmentProvider, ProvideAwsCredentials,
};
use rusoto_ec2 as ec2;
use rusoto_ec2_instance_connect as ec2ic;
use rusoto_s3 as s3;
use rusoto_sts as sts;

use ec2::Ec2;
use ec2ic::Ec2InstanceConnect;
use s3::S3;
use sts::Sts;

mod base;
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
    pub(crate) use bytes::BytesMut;
    pub(crate) use hiercmd::prelude::*;
    pub(crate) use rand::thread_rng;
    pub(crate) use rsa::pkcs8::{FromPrivateKey, ToPrivateKey};
    pub(crate) use rsa::PublicKeyParts;
    pub(crate) use rusoto_core::RusotoError;
    pub(crate) use rusoto_ec2 as ec2;
    pub(crate) use rusoto_ec2_instance_connect as ec2ic;
    pub(crate) use rusoto_s3 as s3;
    pub(crate) use rusoto_sts as sts;
    pub(crate) use tokio::io::AsyncReadExt;

    pub(crate) use super::base::*;
    pub(crate) use super::util::*;
    pub(crate) use super::Stuff;
}

mod cmd;
use cmd::az::do_az;
use cmd::config::do_config;
use cmd::image::{ami_from_file, do_image};
use cmd::instance::do_instance;
use cmd::key::do_key;
use cmd::role::do_role;
use cmd::route::do_route;
use cmd::s3::do_s3;
use cmd::sg::do_sg;
use cmd::snapshot::do_snapshot;
use cmd::subnet::do_subnet;
use cmd::type_::do_type;
use cmd::volume::do_volume;
use cmd::vpc::do_vpc;

mod sdk;

#[derive(Default)]
pub struct Stuff {
    region_ec2: Region,
    region_s3: Region,
    region_sts: Region,
    s3: Option<s3::S3Client>,
    ec2: Option<ec2::Ec2Client>,
    ic: Option<ec2ic::Ec2InstanceConnectClient>,
    sts: Option<sts::StsClient>,
    credprov: Option<Box<dyn ProvideAwsCredentials + Send + Sync>>,
    more: Option<sdk::More>,
}

#[allow(dead_code)]
impl Stuff {
    fn ec2(&self) -> &dyn Ec2 {
        self.ec2.as_ref().unwrap()
    }

    fn s3(&self) -> &dyn S3 {
        self.s3.as_ref().unwrap()
    }

    fn sts(&self) -> &dyn Sts {
        self.sts.as_ref().unwrap()
    }

    fn ic(&self) -> &dyn Ec2InstanceConnect {
        self.ic.as_ref().unwrap()
    }

    fn region_ec2(&self) -> &Region {
        &self.region_ec2
    }

    fn region_s3(&self) -> &Region {
        &self.region_s3
    }

    fn region_sts(&self) -> &Region {
        &self.region_sts
    }

    fn credprov(&self) -> &dyn ProvideAwsCredentials {
        self.credprov.as_deref().unwrap()
    }

    fn more(&self) -> &sdk::More {
        self.more.as_ref().unwrap()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut l = Level::new("aws-wire-lengths", Stuff::default());

    l.optflag("e", "", "use environment variables for credentials");
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
    l.cmda("route", "rt", "routing table management", cmd!(do_route))?;
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

    s.context_mut().credprov = Some(if s.opts().opt_present("e") {
        Box::new(EnvironmentProvider::default())
    } else {
        Box::new(DefaultCredentialsProvider::new()?)
    });

    /*
     * Allow the region to be overridden by a command-line argument.  Otherwise,
     * we depend on the Default implementation of Region, which will inspect the
     * environment, or the AWS configuration file, or fall back to us-east-1.
     */
    if let Some(reg) = s.opts().opt_str("region-s3").as_deref() {
        s.context_mut().region_s3 =
            Region::from_str(reg).context("invalid S3 region")?;
    };
    if let Some(reg) = s.opts().opt_str("region-ec2").as_deref() {
        s.context_mut().region_ec2 =
            Region::from_str(reg).context("invalid EC2 region")?;
    };
    if let Some(reg) = s.opts().opt_str("region-sts").as_deref() {
        s.context_mut().region_sts =
            Region::from_str(reg).context("invalid STS region")?;
    };

    if s.opts().opt_present("e") {
        let mut stuff = s.context_mut();
        stuff.s3 = Some(s3::S3Client::new_with(
            HttpClient::new()?,
            EnvironmentProvider::default(),
            stuff.region_s3.clone(),
        ));
        stuff.ec2 = Some(ec2::Ec2Client::new_with(
            HttpClient::new()?,
            EnvironmentProvider::default(),
            stuff.region_ec2.clone(),
        ));
        stuff.ic = Some(ec2ic::Ec2InstanceConnectClient::new_with(
            HttpClient::new()?,
            EnvironmentProvider::default(),
            stuff.region_ec2.clone(),
        ));
        stuff.sts = Some(sts::StsClient::new_with(
            HttpClient::new()?,
            EnvironmentProvider::default(),
            stuff.region_sts.clone(),
        ));
    } else {
        let mut stuff = s.context_mut();
        stuff.s3 = Some(s3::S3Client::new_with(
            HttpClient::new()?,
            DefaultCredentialsProvider::new()?,
            stuff.region_s3.clone(),
        ));
        stuff.ec2 = Some(ec2::Ec2Client::new_with(
            HttpClient::new()?,
            DefaultCredentialsProvider::new()?,
            stuff.region_ec2.clone(),
        ));
        stuff.ic = Some(ec2ic::Ec2InstanceConnectClient::new_with(
            HttpClient::new()?,
            DefaultCredentialsProvider::new()?,
            stuff.region_ec2.clone(),
        ));
        stuff.sts = Some(sts::StsClient::new_with(
            HttpClient::new()?,
            DefaultCredentialsProvider::new()?,
            stuff.region_sts.clone(),
        ));
    };

    let n = s.context().region_ec2.name().to_string();

    s.context_mut().more = Some(
        sdk::More::new(Some(&n)).await?
    );

    s.run().await
}

/*
 * Copyright 2025 Oxide Computer Company
 */

use anyhow::{bail, Result};
use base64::Engine;
use chrono::prelude::*;
use hiercmd::prelude::*;

pub const WIDTH_PCX: usize = 21;
pub const WIDTH_VPC: usize = 21;
pub const WIDTH_AZ: usize = 14;
pub const WIDTH_IGW: usize = 21;
pub const WIDTH_NAT: usize = 21;
pub const WIDTH_EIP: usize = 26;
pub const WIDTH_ENI: usize = 21;
pub const WIDTH_VOL: usize = 21;

pub const WIDTH_UTC: usize = 20;

pub trait DateTimeOptExt {
    fn as_utc(&self) -> Option<String>;
}

impl DateTimeOptExt for Option<aws_smithy_types::DateTime> {
    fn as_utc(&self) -> Option<String> {
        self.map(|v| {
            Utc.timestamp_nanos(v.as_nanos().try_into().unwrap())
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        })
    }
}

pub trait RowExt {
    fn add_stror(&mut self, n: &str, v: Option<&str>, def: &str);
}

impl RowExt for Row {
    fn add_stror(&mut self, n: &str, v: Option<&str>, def: &str) {
        self.add_str(n, v.as_deref().unwrap_or(def));
    }
}

pub trait AsFlag {
    fn as_flag(&self, f: &str) -> String;
}

impl AsFlag for Option<bool> {
    fn as_flag(&self, f: &str) -> String {
        if let Some(val) = self {
            if *val {
                f
            } else {
                "-"
            }
        } else {
            "-"
        }
        .to_string()
    }
}

impl AsFlag for bool {
    fn as_flag(&self, f: &str) -> String {
        if *self { f } else { "-" }.to_string()
    }
}

pub trait TagExtractor {
    fn tag(&self, n: &str) -> Option<String>;
}

impl TagExtractor for Option<Vec<aws_sdk_ec2::types::Tag>> {
    fn tag(&self, n: &str) -> Option<String> {
        if let Some(tags) = self.as_ref() {
            for tag in tags.iter() {
                if let Some(k) = tag.key() {
                    if k == n {
                        return tag.value.clone();
                    }
                }
            }
        }

        None
    }
}

pub trait DisplayId {
    fn display_id(&self) -> String;
}

impl DisplayId for aws_sdk_ec2::types::Volume {
    fn display_id(&self) -> String {
        self.volume_id().expect("volume_id").to_string()
    }
}

impl DisplayId for aws_sdk_ec2::types::Image {
    fn display_id(&self) -> String {
        self.image_id().expect("image_id").to_string()
    }
}

impl DisplayId for aws_sdk_ec2::types::Subnet {
    fn display_id(&self) -> String {
        self.subnet_id().expect("subnet_id").to_string()
    }
}

impl DisplayId for aws_sdk_ec2::types::RouteTable {
    fn display_id(&self) -> String {
        self.route_table_id().expect("route_table_id").to_string()
    }
}

impl DisplayId for aws_sdk_ec2::types::SecurityGroup {
    fn display_id(&self) -> String {
        self.group_id().expect("group_id").to_string()
    }
}

impl DisplayId for aws_sdk_ec2::types::Vpc {
    fn display_id(&self) -> String {
        self.vpc_id().expect("vpc_id").to_string()
    }
}

impl DisplayId for aws_sdk_ec2::types::Address {
    fn display_id(&self) -> String {
        self.allocation_id().expect("allocation_id").to_string()
    }
}

impl DisplayId for aws_sdk_ec2::types::InternetGateway {
    fn display_id(&self) -> String {
        self.internet_gateway_id()
            .expect("internet_gateway_id")
            .to_string()
    }
}

impl DisplayId for aws_sdk_ec2::types::NatGateway {
    fn display_id(&self) -> String {
        self.nat_gateway_id().expect("nat_gateway_id").to_string()
    }
}
pub fn one_ping_only<T>(
    noun: &str,
    filter: &str,
    v: Option<Vec<T>>,
) -> Result<T>
where
    T: DisplayId,
{
    if let Some(mut v) = v {
        if v.len() == 1 {
            return Ok(v.pop().unwrap());
        }

        if v.len() > 1 {
            let ids = v
                .iter()
                .map(|v| v.display_id())
                .collect::<Vec<_>>()
                .join(", ");

            bail!(
                "more than one {} matched filter \"{}\": {ids}",
                noun,
                filter,
            );
        }
    }

    bail!("could not find a {} matching \"{}\"", noun, filter);
}

pub fn sleep(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

pub fn base64_encode(u: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(u)
}

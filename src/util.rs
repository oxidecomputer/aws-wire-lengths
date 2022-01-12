use anyhow::{bail, Result};
use hiercmd::prelude::*;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rusoto_ec2::Tag;
use std::io::Write;

pub const WIDTH_PCX: usize = 21;
pub const WIDTH_VPC: usize = 21;
pub const WIDTH_AZ: usize = 14;

pub trait RowExt {
    fn add_stror(&mut self, n: &str, v: &Option<String>, def: &str);
}

impl RowExt for Row {
    fn add_stror(&mut self, n: &str, v: &Option<String>, def: &str) {
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

impl TagExtractor for Option<Vec<aws_sdk_ec2::model::Tag>> {
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

impl TagExtractor for Option<Vec<Tag>> {
    fn tag(&self, n: &str) -> Option<String> {
        if let Some(tags) = self.as_ref() {
            for tag in tags.iter() {
                if let Some(k) = tag.key.as_deref() {
                    if k == n {
                        return tag.value.clone();
                    }
                }
            }
        }

        None
    }
}

pub fn ss(s: &str) -> Option<String> {
    Some(s.to_string())
}

pub fn genkey(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(|c| c as char)
        .collect()
}

pub fn one_ping_only<T>(
    noun: &str,
    filter: &str,
    v: Option<Vec<T>>,
) -> Result<T> {
    if let Some(mut v) = v {
        if v.len() == 1 {
            return Ok(v.pop().unwrap());
        }

        if v.len() > 1 {
            bail!("more than one {} matched filter \"{}\"", noun, filter);
        }
    }

    bail!("could not find a {} matching \"{}\"", noun, filter);
}

pub fn sleep(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

pub trait EventWriterExt {
    fn simple_tag(&mut self, n: &str, v: &str) -> Result<()>;
}

impl<T: Write> EventWriterExt for xml::EventWriter<T> {
    fn simple_tag(&mut self, n: &str, v: &str) -> Result<()> {
        self.write(xml::writer::XmlEvent::start_element(n))?;
        self.write(xml::writer::XmlEvent::characters(v))?;
        self.write(xml::writer::XmlEvent::end_element())?;
        Ok(())
    }
}

use hiercmd::prelude::*;
use rusoto_ec2::Tag;
use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};

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

pub trait TagExtractor {
    fn tag(&self, n: &str) -> Option<String>;
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

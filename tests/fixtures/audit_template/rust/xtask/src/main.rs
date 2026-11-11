use std::collections::BTreeMap;
use serde::{Deserialize, Serialize as Ser};
use toml::Value;
// use reqwest::Client;
/* use rand::Rng; */

pub const RAW_NOTE: &str = "use hyper::Server; #[allow(dead_code)]";

#[derive(Debug, Deserialize, Ser)]
pub struct ManifestSummary {
    pub name: String,
}

fn main() {
    let _map: BTreeMap<String, Value> = BTreeMap::new();
}

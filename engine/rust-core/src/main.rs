use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::{BTreeMap, BTreeSet}, env, fs};
use url::Url;

#[derive(Deserialize)]
struct Inventory { #[serde(default)] endpoints: Vec<Value>, #[serde(default)] http: Vec<Value> }

#[derive(Serialize)]
struct RouteFamily { host: String, first_segment: String, endpoints: usize, parameter_names: Vec<String> }

fn value_of(v: &Value) -> String {
    v.get("value").and_then(Value::as_str)
        .or_else(|| v.get("url").and_then(Value::as_str))
        .unwrap_or_default().to_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).unwrap_or_else(|| "results/inventory.json".into());
    let raw = fs::read_to_string(path)?;
    let inv: Inventory = serde_json::from_str(&raw)?;

    let parsed: Vec<_> = inv.endpoints.par_iter().filter_map(|v| {
        let s = value_of(v);
        Url::parse(&s).ok().map(|u| (s, u))
    }).collect();

    let mut groups: BTreeMap<(String,String), (usize,BTreeSet<String>)> = BTreeMap::new();
    for (_, u) in parsed {
        let first = u.path_segments().and_then(|mut x| x.next()).unwrap_or("").to_string();
        let entry = groups.entry((u.host_str().unwrap_or("").to_string(), first)).or_default();
        entry.0 += 1;
        for (k, _) in u.query_pairs() { entry.1.insert(k.into_owned()); }
    }

    let families: Vec<RouteFamily> = groups.into_iter().map(|((host, first_segment),(endpoints, params))| RouteFamily {
        host, first_segment, endpoints, parameter_names: params.into_iter().collect()
    }).collect();

    let output = serde_json::json!({
        "engine": "maher-analysis-core/rust",
        "endpoint_count": inv.endpoints.len(),
        "http_record_count": inv.http.len(),
        "route_families": families
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

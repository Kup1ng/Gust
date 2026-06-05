//! Parse per-rule packet/byte counters out of `nft -j list table ip gust`.
//!
//! NAT'd ports carry no userspace connection state, so the kernel counters on
//! each DNAT rule are the source of truth for the SIGUSR1 dump and heartbeat.

use serde_json::Value;

/// A single rule's counter, identified by the comment we attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterStat {
    pub comment: String,
    pub packets: u64,
    pub bytes: u64,
}

/// Extract counters for our commented DNAT rules from the JSON output. Rules
/// without a `gust:` comment (e.g. the postrouting masquerade) are skipped.
pub fn parse_counters(json: &str) -> Vec<CounterStat> {
    let mut out = Vec::new();
    let Ok(root): Result<Value, _> = serde_json::from_str(json) else {
        return out;
    };
    let Some(items) = root.get("nftables").and_then(Value::as_array) else {
        return out;
    };

    for item in items {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        let comment = rule.get("comment").and_then(Value::as_str).unwrap_or("");
        if !comment.starts_with("gust:") {
            continue;
        }
        let Some(exprs) = rule.get("expr").and_then(Value::as_array) else {
            continue;
        };
        for e in exprs {
            if let Some(counter) = e.get("counter") {
                let packets = counter.get("packets").and_then(Value::as_u64).unwrap_or(0);
                let bytes = counter.get("bytes").and_then(Value::as_u64).unwrap_or(0);
                out.push(CounterStat {
                    comment: comment.to_string(),
                    packets,
                    bytes,
                });
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
    {"nftables":[
      {"metainfo":{"version":"1.0.9","release_name":"Old Doc Yak"}},
      {"table":{"family":"ip","name":"gust","handle":1}},
      {"chain":{"family":"ip","table":"gust","name":"prerouting","handle":1}},
      {"rule":{"family":"ip","table":"gust","chain":"prerouting","handle":4,
        "comment":"gust:tcp:8080->1.2.3.4:443",
        "expr":[
          {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8080}},
          {"counter":{"packets":10,"bytes":840}},
          {"dnat":{"addr":"1.2.3.4","port":443}}
        ]}},
      {"rule":{"family":"ip","table":"gust","chain":"postrouting","handle":5,
        "expr":[
          {"match":{"op":"in","left":{"ct":{"key":"status"}},"right":"dnat"}},
          {"counter":{"packets":7,"bytes":560}},
          {"masquerade":{"flags":"fully-random"}}
        ]}}
    ]}
    "#;

    #[test]
    fn parses_only_commented_rules() {
        let stats = parse_counters(SAMPLE);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].comment, "gust:tcp:8080->1.2.3.4:443");
        assert_eq!(stats[0].packets, 10);
        assert_eq!(stats[0].bytes, 840);
    }

    #[test]
    fn empty_on_garbage() {
        assert!(parse_counters("not json").is_empty());
        assert!(parse_counters("{}").is_empty());
    }
}

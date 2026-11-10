//! `VerifyRequest.config` parsing. Every problem here is an operator mistake
//! (`Err`), never a reject.

use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The gifter's OWN node (`http://host:port`), queried for chain facts.
    pub node_url: String,
    /// Quorum of further nodes (stretch; non-empty is unsupported in this PoC).
    pub node_urls: Vec<String>,
    /// Bound into the challenge digest; must equal the producer's `audience`.
    pub audience: String,
    /// Path B: minimum value of the output paying `K` in the spending Transfer.
    pub min_payout: u64,
    /// Path A (`utxo.note.pk == K`) allowed.
    pub allow_direct_ownership: bool,
    /// Spend-locator payloads allowed (they are rejected anyway in this PoC).
    pub allow_spend_locator: bool,
    pub http_timeout_ms: u64,
    /// Override of the bundled zkSign verification key (JSON file).
    pub zksign_vk_path: Option<String>,
    /// PoC: append one JSON line per decision to this file.
    pub audit_log: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node_url: String::new(),
            node_urls: Vec::new(),
            audience: String::new(),
            min_payout: 0,
            allow_direct_ownership: true,
            allow_spend_locator: true,
            http_timeout_ms: 5000,
            zksign_vk_path: None,
            audit_log: None,
        }
    }
}

fn opt_str<'a>(o: &'a Map<String, Value>, k: &str) -> Result<Option<&'a str>, String> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(v) => Err(format!("config.{k}: expected string, got {v}")),
    }
}

fn opt_bool(o: &Map<String, Value>, k: &str, d: bool) -> Result<bool, String> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(d),
        Some(Value::Bool(b)) => Ok(*b),
        Some(v) => Err(format!("config.{k}: expected bool, got {v}")),
    }
}

fn opt_u64(o: &Map<String, Value>, k: &str, d: u64) -> Result<u64, String> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(d),
        Some(v) => v
            .as_u64()
            .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
            .ok_or_else(|| format!("config.{k}: expected unsigned integer, got {v}")),
    }
}

impl Config {
    /// Parses the verifier config (object, or a JSON string holding one).
    pub fn parse(raw: Option<&Value>) -> Result<Config, String> {
        let owned;
        let v = match raw {
            None | Some(Value::Null) => return Err("config is required (needs node_url)".into()),
            Some(Value::String(s)) => {
                owned = serde_json::from_str::<Value>(s)
                    .map_err(|e| format!("config: invalid JSON string: {e}"))?;
                &owned
            }
            Some(v) => v,
        };
        let o = v
            .as_object()
            .ok_or_else(|| format!("config: expected object, got {v}"))?;
        let d = Config::default();

        let node_url = opt_str(o, "node_url")?
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .ok_or("config.node_url is required")?;
        if !(node_url.starts_with("http://") || node_url.starts_with("https://")) {
            return Err(format!(
                "config.node_url: expected http(s):// URL, got {node_url:?}"
            ));
        }
        let node_urls = match o.get("node_urls") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => a
                .iter()
                .map(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| format!("config.node_urls: expected strings, got {x}"))
                })
                .collect::<Result<_, _>>()?,
            Some(v) => return Err(format!("config.node_urls: expected array, got {v}")),
        };
        if !node_urls.is_empty() {
            return Err("config.node_urls: quorum verification is unsupported in this PoC".into());
        }
        let audience = rln_auth_vector::parse_audience(o.get("audience"), "config.audience")?;
        let http_timeout_ms = opt_u64(o, "http_timeout_ms", d.http_timeout_ms)?;
        if http_timeout_ms == 0 {
            return Err("config.http_timeout_ms must be > 0".into());
        }
        Ok(Config {
            node_url,
            node_urls,
            audience,
            min_payout: opt_u64(o, "min_payout", d.min_payout)?,
            allow_direct_ownership: opt_bool(
                o,
                "allow_direct_ownership",
                d.allow_direct_ownership,
            )?,
            allow_spend_locator: opt_bool(o, "allow_spend_locator", d.allow_spend_locator)?,
            http_timeout_ms,
            zksign_vk_path: opt_str(o, "zksign_vk_path")?
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
            audit_log: opt_str(o, "audit_log")?
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_and_required() {
        let c = Config::parse(Some(&json!({"node_url": "http://127.0.0.1:8080/"}))).unwrap();
        assert_eq!(c.node_url, "http://127.0.0.1:8080");
        assert_eq!(c.audience, "");
        assert_eq!(c.min_payout, 0);
        assert!(c.allow_direct_ownership && c.allow_spend_locator);
        assert_eq!(c.http_timeout_ms, 5000);
        assert!(Config::parse(None).unwrap_err().contains("node_url"));
        assert!(Config::parse(Some(&json!({})))
            .unwrap_err()
            .contains("node_url"));
        assert!(Config::parse(Some(&json!({"node_url": 5}))).is_err());
    }

    #[test]
    fn string_config_and_types() {
        let c = Config::parse(Some(&json!(
            "{\"node_url\":\"http://x:1\",\"audience\":\"poc\",\"min_payout\":\"7\",\"allow_direct_ownership\":false}"
        )))
        .unwrap();
        assert_eq!(c.audience, "poc");
        assert_eq!(c.min_payout, 7);
        assert!(!c.allow_direct_ownership);
        assert!(Config::parse(Some(&json!({"node_url":"http://x:1","min_payout":-1}))).is_err());
    }

    #[test]
    fn audience_cap_and_quorum() {
        let a255 = "a".repeat(255);
        assert!(Config::parse(Some(&json!({"node_url":"http://x:1","audience":a255}))).is_ok());
        let a256 = "a".repeat(256);
        let e = Config::parse(Some(&json!({"node_url":"http://x:1","audience":a256}))).unwrap_err();
        assert!(e.contains("255"), "{e}");
        let e = Config::parse(Some(
            &json!({"node_url":"http://x:1","node_urls":["http://y:1"]}),
        ))
        .unwrap_err();
        assert!(e.contains("unsupported"), "{e}");
    }
}

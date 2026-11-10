//! The logos signer: a local logos-blockchain node zkSigns the binding
//! digest with one of its KMS keys (`POST /wallet/sign/zk`), so the key never
//! leaves the node. `K` is `args.public_key`, else the node's single
//! `/pow/status` auto-claim target.

use rln_auth_vector::{args_object_cow, norm_hex32, Binding, Identity, Signer};
use serde_json::Value;
use zksign_light::{HttpZkNode, ZkNode};

use crate::scheme::logos::{LogosKey, NAME};

pub const DEFAULT_NODE_URL: &str = "http://127.0.0.1:8080";
/// Timeout for `/pow/status`; signing always gets at least
/// `zksign_light::SIGN_MIN_TIMEOUT_MS`.
pub const DEFAULT_HTTP_TIMEOUT_MS: u64 = 8000;

/// The node-related `args` of a logos produce request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeArgs {
    pub node_url: String,
    pub public_key: Option<String>,
    pub http_timeout_ms: u64,
}

impl Default for NodeArgs {
    fn default() -> Self {
        NodeArgs {
            node_url: DEFAULT_NODE_URL.into(),
            public_key: None,
            http_timeout_ms: DEFAULT_HTTP_TIMEOUT_MS,
        }
    }
}

impl NodeArgs {
    pub fn parse(raw: Option<&Value>) -> Result<NodeArgs, String> {
        let Some(o) = args_object_cow(raw)? else {
            return Ok(NodeArgs::default());
        };
        let mut a = NodeArgs::default();
        match o.get("node_url") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) if !s.trim().is_empty() => {
                a.node_url = s.trim().trim_end_matches('/').to_string()
            }
            Some(Value::String(_)) => {}
            Some(v) => return Err(format!("node_url: expected string, got {v}")),
        }
        match o.get("public_key") {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => a.public_key = Some(norm_hex32("public_key", s)?),
            Some(v) => return Err(format!("public_key: expected string, got {v}")),
        }
        match o.get("http_timeout_ms") {
            None | Some(Value::Null) => {}
            Some(Value::Number(n)) => {
                a.http_timeout_ms = n
                    .as_u64()
                    .ok_or_else(|| format!("http_timeout_ms: expected unsigned integer, got {n}"))?
            }
            Some(v) => {
                return Err(format!(
                    "http_timeout_ms: expected unsigned integer, got {v}"
                ))
            }
        }
        Ok(a)
    }
}

/// K and where it came from: `args.public_key`, else the node's single
/// `/pow/status` auto-claim target.
pub fn resolve_key(node: &dyn ZkNode, args: &NodeArgs) -> Result<(String, &'static str), String> {
    if let Some(k) = &args.public_key {
        return Ok((k.clone(), "args"));
    }
    let st = node.pow_status()?;
    let targets = st
        .pointer("/auto_claim/targets")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    match targets {
        [t] => {
            let k = t["public_key"]
                .as_str()
                .ok_or("/pow/status: auto_claim.targets[0].public_key missing")?;
            Ok((norm_hex32("/pow/status public_key", k)?, "pow_status"))
        }
        [] => Err(format!(
            "node {} reports no /pow/status auto-claim target; set args.public_key to a node key",
            args.node_url
        )),
        many => Err(format!(
            "node {} reports {} /pow/status auto-claim targets; set args.public_key to choose one",
            args.node_url,
            many.len()
        )),
    }
}

/// Builds the node client per request from `args` (the module), or uses a
/// fixed one (tests).
pub struct LogosSigner {
    // OWNERSHIP: a node the signer owns (tests) or none (an HTTP node per request); `Send + Sync` as `Signer` requires.
    pub node: Option<Box<dyn ZkNode + Send + Sync>>,
}

impl LogosSigner {
    pub fn http() -> Self {
        LogosSigner { node: None }
    }
    fn with_node<T>(
        &self,
        args: &NodeArgs,
        f: impl FnOnce(&dyn ZkNode) -> Result<T, String>,
    ) -> Result<T, String> {
        match &self.node {
            Some(n) => f(n.as_ref()),
            None => f(&HttpZkNode {
                url: args.node_url.clone(),
                timeout_ms: args.http_timeout_ms,
            }),
        }
    }
}

impl Signer for LogosSigner {
    fn scheme(&self) -> &'static str {
        NAME
    }
    /// `K(32) ‖ zksig(128)`.
    fn sign(
        &self,
        _b: &Binding,
        digest: &[u8; 32],
        args: Option<&Value>,
    ) -> Result<Vec<u8>, String> {
        let a = NodeArgs::parse(args)?;
        self.with_node(&a, |node| {
            let (k_hex, _) = resolve_key(node, &a)?;
            let sig = node.sign_zk(digest, &k_hex)?;
            let mut out = hex::decode(&k_hex).map_err(|e| format!("k: {e}"))?;
            out.extend_from_slice(&sig);
            Ok(out)
        })
    }
    fn identity(&self, args: Option<&Value>) -> Result<Box<dyn Identity>, String> {
        let a = NodeArgs::parse(args)?;
        let (k, _) = self.with_node(&a, |node| resolve_key(node, &a))?;
        Ok(Box::new(LogosKey(k)))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// A node that answers canned `/pow/status` and signs with a fixed proof.
    pub(crate) struct FakeNode {
        pub status: Value,
        pub sig: [u8; 128],
        pub last: std::sync::Mutex<Option<([u8; 32], String)>>,
    }
    impl ZkNode for FakeNode {
        fn pow_status(&self) -> Result<Value, String> {
            Ok(self.status.clone())
        }
        fn sign_zk(&self, digest: &[u8; 32], pk_hex: &str) -> Result<[u8; 128], String> {
            *self.last.lock().unwrap() = Some((*digest, pk_hex.to_string()));
            Ok(self.sig)
        }
    }
    pub(crate) const K: &str = "e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce07";
    pub(crate) fn fake(targets: &[&str]) -> FakeNode {
        let t: Vec<Value> = targets.iter().map(|k| json!({ "public_key": k })).collect();
        FakeNode {
            status: json!({ "auto_claim": { "targets": t } }),
            sig: [0xab; 128],
            last: Default::default(),
        }
    }

    #[test]
    fn args_parse_and_key_resolution() {
        let a = NodeArgs::parse(Some(&json!({ "node_url": "http://x:1/", "public_key": format!("0x{}", K.to_uppercase()), "http_timeout_ms": 5 }))).unwrap();
        assert_eq!(
            (
                a.node_url.as_str(),
                a.public_key.as_deref(),
                a.http_timeout_ms
            ),
            ("http://x:1", Some(K), 5)
        );
        assert_eq!(
            NodeArgs::parse(Some(&json!("{\"node_url\":\"http://y:2\"}")))
                .unwrap()
                .node_url,
            "http://y:2"
        );
        assert!(NodeArgs::parse(Some(&json!({ "public_key": "zz" })))
            .unwrap_err()
            .starts_with("public_key"));

        let n = fake(&[K]);
        assert_eq!(
            resolve_key(&n, &NodeArgs::default()).unwrap(),
            (K.to_string(), "pow_status")
        );
        assert_eq!(resolve_key(&n, &a).unwrap().1, "args");
        assert!(resolve_key(&fake(&[]), &NodeArgs::default())
            .unwrap_err()
            .contains("no /pow/status"));
        assert!(resolve_key(&fake(&[K, K]), &NodeArgs::default())
            .unwrap_err()
            .contains("2 /pow/status"));
    }

    #[test]
    fn signer_builds_the_part_from_the_node() {
        let s = LogosSigner {
            node: Some(Box::new(fake(&[K]))),
        };
        let b = Binding {
            id_commitment: [1; 32],
            rate_max: 100,
            audience: String::new(),
        };
        let part = s.sign(&b, &[9; 32], None).unwrap();
        assert_eq!(part.len(), 160);
        assert_eq!(hex::encode(&part[..32]), K);
        assert!(part[32..].iter().all(|&x| x == 0xab));
        assert_eq!(s.identity(None).unwrap().canonical(), K);
    }
}

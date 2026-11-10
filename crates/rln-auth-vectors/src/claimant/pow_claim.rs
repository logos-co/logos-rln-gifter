//! The pow-claim claimant: find the claim the key owns on the local node and
//! hand back its locator as the evidence; the claim's nullifier is what the
//! digest binds. The key the claim is searched for is `args.claim_address`,
//! else `args.public_key` (the logos signer's choice), else the node's
//! `/pow/status` auto-claim targets.

use pow_claim::{gather, Evidence, HttpNode, NodeApi, ProduceArgs};
use rln_auth_vector::{args_object_cow, Binding, Claimant};
use serde_json::Value;

use crate::scheme::logos::NAME as LOGOS;

/// Builds the node client per request from `args` (the module), or uses a
/// fixed one (tests).
pub struct PowClaimant {
    // OWNERSHIP: a node the claimant owns, or none (an HTTP node per request); `Send + Sync` as `Claimant` requires.
    pub node: Option<Box<dyn NodeApi + Send + Sync>>,
}

impl PowClaimant {
    pub fn http() -> Self {
        PowClaimant { node: None }
    }
}

/// [`ProduceArgs`] with `public_key` accepted as an alias of `claim_address`.
pub fn claim_args(raw: Option<&Value>) -> Result<ProduceArgs, String> {
    let mut a = ProduceArgs::parse(raw)?;
    if a.claim_address.is_none() {
        if let Some(o) = args_object_cow(raw)? {
            if let Some(Value::String(k)) = o.get("public_key") {
                a.claim_address = Some(rln_auth_vector::norm_hex32("public_key", k)?);
            }
        }
    }
    Ok(a)
}

impl Claimant for PowClaimant {
    fn authoriser(&self) -> &'static str {
        "pow-claim"
    }
    fn accepts(&self, scheme: &str) -> bool {
        scheme == LOGOS
    }
    fn gather(&self, _b: &Binding, args: Option<&Value>) -> Result<Vec<u8>, String> {
        let a = claim_args(args)?;
        let claim = match &self.node {
            Some(n) => gather(n.as_ref(), &a)?,
            None => gather(&HttpNode::new(&a.node_url, a.http_timeout_ms), &a)?,
        };
        Ok(claim.evidence.encode())
    }
    fn extra(&self, evidence: &[u8]) -> Vec<u8> {
        Evidence::decode(evidence)
            .map(|(e, _)| e.pow_nullifier.to_vec())
            .unwrap_or_default()
    }
}

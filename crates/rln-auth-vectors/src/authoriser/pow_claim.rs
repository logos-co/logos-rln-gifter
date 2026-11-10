//! The `pow-claim` authoriser: the logos key `K` owns a settled PoW reward
//! claim on the chain the gifter's own node follows. Composes with the logos
//! scheme only. The evidence is the claim locator ([`pow_claim::Evidence`]);
//! its `pow_nullifier` is bound into the digest and is the nullifier.

use std::any::Any;

use pow_claim::verify::{check, Config};
use pow_claim::{Claim, Evidence as ClaimEvidence, HttpNode};
use rln_auth_vector::{
    downcast_identity, Authoriser, Cfg, Check, Evidence, Identity, Outcome, Scheme,
};
use serde_json::Value;

use crate::scheme::logos::{LogosKey, NAME as LOGOS};

pub const NAME: &str = "pow-claim";

pub struct PowClaim;

impl Authoriser for PowClaim {
    fn name(&self) -> &'static str {
        NAME
    }
    fn accepts(&self, scheme: &str) -> bool {
        scheme == LOGOS
    }
    /// [`pow_claim::verify::Config`]: `node_url` (required), `audience`,
    /// `min_payout`, `allow_direct_ownership`, `allow_spend_locator`,
    /// `http_timeout_ms`, `audit_log`.
    fn config(&self, _scheme: &dyn Scheme, raw: Option<&Value>) -> Result<Cfg, String> {
        Ok(Box::new(Config::parse(raw)?))
    }
    fn audience<'a>(&self, cfg: &'a dyn Any) -> &'a str {
        cfg.downcast_ref::<Config>()
            .map(|c| c.audience.as_str())
            .unwrap_or("")
    }
    fn decode_evidence<'a>(&self, rest: &'a [u8]) -> Outcome<(Evidence, &'a [u8])> {
        match ClaimEvidence::decode(rest) {
            Ok((ev, rest)) => Outcome::Ok((Box::new(ev), rest)),
            Err(e) => Outcome::Reject(e),
        }
    }
    fn extra(&self, ev: &dyn Any) -> Vec<u8> {
        ev.downcast_ref::<ClaimEvidence>()
            .map(|e| e.pow_nullifier.to_vec())
            .unwrap_or_default()
    }
    fn authorise(&self, cfg: &dyn Any, id: &dyn Identity, ev: &dyn Any) -> Check<()> {
        let cfg = cfg
            .downcast_ref::<Config>()
            .ok_or("pow-claim: config is not a pow-claim config")?;
        let ev = ev
            .downcast_ref::<ClaimEvidence>()
            .ok_or("pow-claim: evidence is not a claim locator")?;
        let key =
            downcast_identity::<LogosKey>(id).ok_or("pow-claim: identity is not a logos key")?;
        let k = rln_auth_vector::hex32_bytes("k", &key.0)?;
        if ev.spend.is_some() {
            return Ok(Outcome::Reject(
                if cfg.allow_spend_locator {
                    "spend locator unsupported in this PoC"
                } else {
                    "spend locator disallowed by config"
                }
                .into(),
            ));
        }
        let claim = Claim {
            k,
            evidence: ev.clone(),
        };
        let node = HttpNode::new(&cfg.node_url, cfg.http_timeout_ms);
        let c = check(&[&node], &claim, cfg)?;
        Ok(match c.outcome {
            Ok(_) => Outcome::Ok(()),
            Err(reason) => Outcome::Reject(reason),
        })
    }
    fn nullifier(&self, id: &dyn Identity, ev: &dyn Any) -> String {
        ev.downcast_ref::<ClaimEvidence>()
            .map(|e| hex::encode(e.pow_nullifier))
            .unwrap_or_else(|| id.canonical())
    }
}

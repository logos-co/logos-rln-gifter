//! The verify half: the chain checks for a signature-checked claim, against
//! the gifter's OWN node — claim block final + canonical, the
//! `PoWRewardClaimed` event, ticket + op_id recompute, and ownership of the
//! minted note by `K` (direct, or spent to `K` in the claim tx).
//!
//! Operator problems (bad config, unreachable node) are `Err`; anything
//! derived from the payload or chain content is a reject. The modules are
//! built with `panic = "abort"`: nothing here may panic on input.

pub mod audit;
pub mod chain;
pub mod config;
pub mod ticket;

use std::time::Instant;

use crate::{claim::Claim, node::NodeApi};

pub use chain::{check_claim, spent_to_k, ClaimCheck};
pub use config::Config;
pub use ticket::puzzle_ticket;

/// [`check_claim`] with the decision recorded (stderr + optional audit log).
/// `Ok(Err(reason))` is a reject, `Err` an operator problem.
pub fn check(nodes: &[&dyn NodeApi], claim: &Claim, cfg: &Config) -> Result<ClaimCheck, String> {
    let t0 = Instant::now();
    let mut rec = audit::Record {
        node: cfg.node_url.clone(),
        nullifier: Some(hex::encode(claim.evidence.pow_nullifier)),
        ..Default::default()
    };
    let r = check_claim(nodes, claim, cfg);
    if let Ok(c) = &r {
        rec.lib_slot = c.lib_slot;
        if let Ok(path) = &c.outcome {
            rec.path = Some(path.as_str());
        }
    }
    // OWNERSHIP: `audit::record` takes the owned verdict shape; `r` is returned to the caller.
    let verdict = match &r {
        Ok(c) => Ok(c.outcome.clone().map(|_| ())),
        Err(e) => Err(e.clone()),
    };
    audit::record(
        cfg.audit_log.as_deref(),
        &rec,
        &verdict,
        t0.elapsed().as_millis(),
    );
    r
}

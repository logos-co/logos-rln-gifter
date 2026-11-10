//! Locating a redeemable PoW reward claim for one of the user's keys (§4.2
//! steps 1–3).

use std::collections::HashSet;

use serde_json::Value;

use crate::{
    args::ProduceArgs,
    node::NodeApi,
    ownership::{owner, tx_event, Path},
};

/// Slots per `immutable_blocks` request.
pub const SCAN_CHUNK_SLOTS: u64 = 100;

#[derive(Debug, Clone)]
pub struct Found {
    /// Owning key K (64 hex, lowercase).
    pub k: String,
    pub path: Path,
    pub block_id: String,
    pub slot: u64,
    pub nullifier: String,
    /// The inner `Tx` event object.
    pub event: Value,
}

fn candidate_keys(node: &dyn NodeApi, args: &ProduceArgs) -> Result<Vec<String>, String> {
    if let Some(k) = &args.claim_address {
        return Ok(vec![k.clone()]);
    }
    let st = node.pow_status()?;
    let ks: Vec<String> = st["auto_claim"]["targets"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|t| t["public_key"].as_str())
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default();
    if ks.is_empty() {
        return Err(
            "no claim address: node has no pow.auto_claim.targets; pass claim_address".into(),
        );
    }
    Ok(ks)
}

fn nullifier_of(ev: &Value) -> Option<String> {
    tx_event(ev)["payload"]["PoWRewardClaimed"]["pow_nullifier"]
        .as_str()
        .map(str::to_ascii_lowercase)
}

/// [`tx_event`] of an owned event, moved out: the `Tx` member if `ev` is an
/// object holding one, else `ev` itself.
fn into_tx_event(ev: Value) -> Value {
    match ev {
        Value::Object(mut m) => m.remove("Tx").unwrap_or(Value::Object(m)),
        other => other,
    }
}

fn block_id(b: &Value) -> Result<String, String> {
    b["header"]["id"]
        .as_str()
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| format!("block without header.id: {b}"))
}

fn block_slot(b: &Value) -> u64 {
    b["header"]["slot"].as_u64().unwrap_or(0)
}

/// First owned, non-excluded claim in `block`, in event order.
fn scan_block(
    node: &dyn NodeApi,
    block: &Value,
    ks: &[String],
    exclude: &[String],
) -> Result<Option<Found>, String> {
    let id = block_id(block)?;
    for ev in node.events(&id)? {
        let Some(nul) = nullifier_of(&ev) else {
            continue;
        };
        if exclude.iter().any(|x| x == &nul) {
            continue;
        }
        if let Some((k, path)) = owner(&ev, block, ks) {
            return Ok(Some(Found {
                k,
                path,
                block_id: id,
                slot: block_slot(block),
                nullifier: nul,
                event: into_tx_event(ev),
            }));
        }
    }
    Ok(None)
}

pub fn discover(node: &dyn NodeApi, args: &ProduceArgs) -> Result<Found, String> {
    let ks = candidate_keys(node, args)?;

    // Pinned claim.
    if let Some(nul) = &args.pow_nullifier {
        let bid = args
            .claim_block_id
            .as_ref()
            .ok_or("pow_nullifier is pinned but claim_block_id is missing")?;
        let block = node
            .block(bid)?
            .ok_or_else(|| format!("claim block not found: {bid}"))?;
        let ev = node
            .events(bid)?
            .into_iter()
            .find(|e| nullifier_of(e).as_deref() == Some(nul.as_str()))
            .ok_or_else(|| format!("no PoWRewardClaimed with nullifier {nul} in block {bid}"))?;
        let (k, path) = owner(&ev, &block, &ks)
            .ok_or_else(|| format!("claim {nul} in block {bid} is not owned by any of {ks:?}"))?;
        return Ok(Found {
            k,
            path,
            block_id: bid.clone(),
            slot: block_slot(&block),
            nullifier: nul.clone(),
            event: into_tx_event(ev),
        });
    }

    let info = node.info()?;
    let ci = &info["cryptarchia_info"];
    let lib_slot = ci["lib_slot"]
        .as_u64()
        .ok_or_else(|| format!("cryptarchia info without cryptarchia_info.lib_slot: {info}"))?;
    let lo = lib_slot.saturating_sub(args.scan_window_slots);
    let mut seen = HashSet::new();

    // Final blocks, newest first.
    let mut hi = lib_slot;
    loop {
        let from = hi.saturating_sub(SCAN_CHUNK_SLOTS - 1).max(lo);
        let mut blocks = node.immutable_blocks(from, hi)?;
        blocks.sort_by_key(|b| std::cmp::Reverse(block_slot(b)));
        for b in &blocks {
            seen.insert(block_id(b)?);
            if let Some(f) = scan_block(node, b, &ks, &args.exclude_nullifiers)? {
                return Ok(f);
            }
        }
        if from <= lo {
            break;
        }
        hi = from - 1;
    }

    // Optionally, non-final blocks walking back from the tip.
    if args.allow_unfinal {
        let mut cur = ci["tip"].as_str().map(str::to_ascii_lowercase);
        let mut n = 0;
        while let Some(id) = cur.take() {
            if n >= args.scan_depth_blocks {
                break;
            }
            n += 1;
            let Some(b) = node.block(&id)? else { break };
            if !seen.contains(&id) {
                if let Some(f) = scan_block(node, &b, &ks, &args.exclude_nullifiers)? {
                    return Ok(f);
                }
            }
            cur = b["header"]["parent_block"]
                .as_str()
                .map(str::to_ascii_lowercase);
        }
    }

    Err(format!(
        "no redeemable PoW claim found for K in {ks:?} (final slots {lo}..={lib_slot}{})",
        if args.allow_unfinal {
            format!(", plus {} blocks back from tip", args.scan_depth_blocks)
        } else {
            String::new()
        }
    ))
}

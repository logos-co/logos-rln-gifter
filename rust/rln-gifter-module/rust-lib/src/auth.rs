// The append-only consumed-nullifier store shared by every auth vector: a
// verifier module returning a nullifier opts its credential into
// reserve-before-register / rollback-on-failure / persist-on-success replay
// protection. Vector verification itself lives in plugin modules
// (keycard-auth-module, eth-auth-module, …) — see the rln_auth_vector crate.
// FEATURE: RLN membership gifter replay protection

use std::collections::HashSet;

/// Load the append-only consumed-nullifier store (lowercase, one per line).
/// Missing/unreadable file → empty set (a fresh gifter).
pub fn load_nullifiers(path: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    if path.is_empty() {
        return set;
    }
    if let Ok(contents) = std::fs::read_to_string(path) {
        for line in contents.lines() {
            let n = line.trim().to_lowercase();
            if !n.is_empty() {
                set.insert(n);
            }
        }
    }
    set
}

/// Append a consumed nullifier to the persistent store (no-op without a path),
/// so a gifter restart cannot re-grant a spent credential.
pub fn append_nullifier(path: &str, nullifier_hex: &str) {
    if path.is_empty() {
        return;
    }
    use std::io::Write;
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(mut f) => {
            let _ = writeln!(f, "{nullifier_hex}");
        }
        Err(e) => eprintln!("rln_gifter: failed to persist nullifier to {path}: {e}"),
    }
}

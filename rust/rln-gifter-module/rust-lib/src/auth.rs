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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("rln-gifter-nul-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn append_then_load_round_trips() {
        let path = tmp("roundtrip");
        append_nullifier(&path, "keycard-attestation:aa11");
        append_nullifier(&path, "eth-allowlist:0xdead");
        let set = load_nullifiers(&path);
        assert!(set.contains("keycard-attestation:aa11"));
        assert!(set.contains("eth-allowlist:0xdead"));
        assert_eq!(set.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_normalizes_case_and_whitespace() {
        let path = tmp("normalize");
        std::fs::write(&path, "  KEYCARD-ATTESTATION:AA11 \n\n").unwrap();
        let set = load_nullifiers(&path);
        assert!(set.contains("keycard-attestation:aa11"));
        assert_eq!(set.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_path_is_a_no_op_store() {
        append_nullifier("", "x");
        assert!(load_nullifiers("").is_empty());
    }
}

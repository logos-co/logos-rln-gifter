// The consumed-nullifier store shared by every auth vector: a verifier module
// returning a nullifier opts its credential into reserve-before-register /
// rollback-on-failure replay protection. A reservation is written to the
// file at once, so an allocator restarted while its registration is still
// confirming cannot grant the credential a second membership; a registration
// that reached nothing on chain takes its line back out. Vector verification
// itself lives in plugin modules (keycard-auth-module, allowlist-auth-module,
// …) — see the rln_auth_vector crate.

use std::collections::HashSet;

/// The consumed-nullifier set and the file it persists to, kept together
/// behind one lock (the server's `NULLIFIERS`). Each method does its file
/// operation inside the caller's critical section, so the set and the
/// current file never disagree about a line, and a path change applies to
/// every later reservation and release. File IO only, never a cross-module
/// call: the owner thread may wait on the lock.
#[derive(Default)]
pub struct NullifierStore {
    spent: HashSet<String>,
    /// The file named by the latest `serve` (empty = memory only); `None`
    /// before the first.
    path: Option<String>,
}

impl NullifierStore {
    /// `serve`'s merge, never a replace: a re-serve may only ADD replay
    /// knowledge, or in-memory reservations would be forgotten. A file other
    /// than the current one first inherits the whole set, or a restart on it
    /// would forget everything spent under the old one; `path` is then the
    /// file of every later reservation and release. On `Err` the current file
    /// stays.
    pub fn open(&mut self, path: &str) -> Result<(), String> {
        self.spent.extend(load_nullifiers(path)?);
        if self.path.as_deref().is_some_and(|p| p != path) {
            append_missing(path, &self.spent)?;
        }
        if self.path.as_deref() != Some(path) {
            self.path = Some(path.to_owned());
        }
        Ok(())
    }

    fn file(&self) -> &str {
        self.path.as_deref().unwrap_or("")
    }

    /// Whether the credential behind `nul` bought a membership already.
    pub fn is_spent(&self, nul: &str) -> bool {
        self.spent.contains(nul)
    }

    /// Reserve `nul` before its registration: into the set and onto the
    /// current file, both or neither. `Ok(false)`: already spent. `Err`: the
    /// file refused the line and nothing is reserved, since a reservation
    /// that never reached disk does not survive a restart.
    pub fn reserve(&mut self, nul: &str) -> Result<bool, String> {
        if self.spent.contains(nul) {
            return Ok(false);
        }
        append_nullifier(self.file(), nul)?;
        // OWNERSHIP: the set keeps its own key for the process lifetime; the
        // request keeps the caller's for a release.
        self.spent.insert(nul.to_owned());
        Ok(true)
    }

    /// Take a reservation back: out of the set, and its line out of the
    /// current file. The set lets go even when the file cannot be rewritten;
    /// `Err` says why (the line then keeps the credential spent across a
    /// restart).
    pub fn release(&mut self, nul: &str) -> Result<(), String> {
        self.spent.remove(nul);
        remove_nullifier(self.file(), nul)
    }
}

/// Load the append-only consumed-nullifier store (lowercase, one per line).
/// A missing file is an empty set (a fresh allocator); a file that exists but
/// cannot be read is an error, since loading it as empty re-opens every
/// credential it spent.
pub fn load_nullifiers(path: &str) -> Result<HashSet<String>, String> {
    let mut set = HashSet::new();
    if path.is_empty() {
        return Ok(set);
    }
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(set),
        Err(e) => return Err(format!("read {path}: {e}")),
    };
    for line in contents.lines() {
        let n = line.trim().to_lowercase();
        if !n.is_empty() {
            set.insert(n);
        }
    }
    Ok(set)
}

/// Carry a set of nullifiers into another store file (no-op without a path):
/// the ones the file lacks are appended, so an allocator re-served with a new
/// `consumedNullifiersPath` keeps every credential it already spent.
fn append_missing(path: &str, nullifiers: &HashSet<String>) -> Result<(), String> {
    if path.is_empty() {
        return Ok(());
    }
    let present = load_nullifiers(path)?;
    let mut missing: Vec<&str> = nullifiers
        .iter()
        .map(String::as_str)
        .filter(|n| !present.contains(*n))
        .collect();
    missing.sort();
    for n in missing {
        append_nullifier(path, n)?;
    }
    Ok(())
}

/// Take a nullifier back out of the persistent store (no-op without a path):
/// its registration was never submitted, so the credential is unspent.
fn remove_nullifier(path: &str, nullifier_hex: &str) -> Result<(), String> {
    if path.is_empty() {
        return Ok(());
    }
    let contents = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let kept: Vec<&str> = contents
        .lines()
        .filter(|line| line.trim().to_lowercase() != nullifier_hex)
        .collect();
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    std::fs::write(path, out).map_err(|e| format!("write {path}: {e}"))
}

/// Append a consumed nullifier to the persistent store (no-op without a path),
/// so an allocator restart cannot re-grant a spent credential.
fn append_nullifier(path: &str, nullifier_hex: &str) -> Result<(), String> {
    if path.is_empty() {
        return Ok(());
    }
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open {path}: {e}"))?;
    writeln!(f, "{nullifier_hex}").map_err(|e| format!("write {path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let p =
            std::env::temp_dir().join(format!("rln-gifter-nul-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn append_then_load_round_trips() {
        let path = tmp("roundtrip");
        append_nullifier(&path, "keycard-attestation:aa11").unwrap();
        append_nullifier(&path, "eth-allowlist:0xdead").unwrap();
        let set = load_nullifiers(&path).unwrap();
        assert!(set.contains("keycard-attestation:aa11"));
        assert!(set.contains("eth-allowlist:0xdead"));
        assert_eq!(set.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_normalizes_case_and_whitespace() {
        let path = tmp("normalize");
        std::fs::write(&path, "  KEYCARD-ATTESTATION:AA11 \n\n").unwrap();
        let set = load_nullifiers(&path).unwrap();
        assert!(set.contains("keycard-attestation:aa11"));
        assert_eq!(set.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_path_is_a_no_op_store() {
        append_nullifier("", "x").unwrap();
        remove_nullifier("", "x").unwrap();
        assert!(load_nullifiers("").unwrap().is_empty());
    }

    #[test]
    fn a_new_store_file_inherits_what_the_old_one_spent() {
        let old = tmp("inherit-old");
        let new = tmp("inherit-new");
        append_nullifier(&old, "d:peer-any:aa").unwrap();
        append_nullifier(&old, "d:peer-any:bb").unwrap();
        append_nullifier(&new, "d:peer-any:bb").unwrap();
        append_missing(&new, &load_nullifiers(&old).unwrap()).unwrap();
        let set = load_nullifiers(&new).unwrap();
        assert_eq!(set.len(), 2, "{set:?}");
        assert_eq!(
            std::fs::read_to_string(&new).unwrap().matches("bb").count(),
            1,
            "no duplicate line"
        );
        append_missing("", &set).unwrap();
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::remove_file(&new);
    }

    #[test]
    fn a_released_reservation_leaves_the_others_in_place() {
        let path = tmp("release");
        append_nullifier(&path, "d:peer-any:aa").unwrap();
        append_nullifier(&path, "d:peer-any:bb").unwrap();
        append_nullifier(&path, "m:peer-any:aa").unwrap();
        remove_nullifier(&path, "d:peer-any:bb").unwrap();
        let set = load_nullifiers(&path).unwrap();
        assert_eq!(set.len(), 2, "{set:?}");
        assert!(set.contains("d:peer-any:aa") && set.contains("m:peer-any:aa"));
        remove_nullifier(&path, "nope").unwrap();
        assert_eq!(load_nullifiers(&path).unwrap().len(), 2);
        remove_nullifier(&path, "d:peer-any:aa").unwrap();
        remove_nullifier(&path, "m:peer-any:aa").unwrap();
        assert!(load_nullifiers(&path).unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unreadable_store_is_an_error_not_an_empty_set() {
        let path = tmp("unreadable");
        let _ = std::fs::remove_dir_all(&path);
        // A directory where the store belongs: present, but not readable as one.
        std::fs::create_dir(&path).unwrap();
        let err = load_nullifiers(&path).unwrap_err();
        assert!(err.starts_with("read "), "got {err}");
        assert!(append_nullifier(&path, "d:peer-any:aa").is_err());
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn an_append_that_cannot_reach_disk_is_an_error() {
        let path = format!("{}/missing-dir/store", tmp("no-parent"));
        let err = append_nullifier(&path, "d:peer-any:aa").unwrap_err();
        assert!(err.starts_with("open "), "got {err}");
    }

    #[test]
    fn a_store_reserves_and_releases_in_the_file_serve_named_last() {
        let (old, new) = (tmp("store-old"), tmp("store-new"));
        let mut store = NullifierStore::default();
        store.open(&old).unwrap();
        assert!(store.reserve("d:t:aa").unwrap());
        assert!(!store.reserve("d:t:aa").unwrap(), "already spent");
        store.open(&new).unwrap();
        assert!(store.reserve("d:t:bb").unwrap());
        let (o, n) = (
            load_nullifiers(&old).unwrap(),
            load_nullifiers(&new).unwrap(),
        );
        assert!(o.contains("d:t:aa") && !o.contains("d:t:bb"), "{o:?}");
        assert!(n.contains("d:t:aa") && n.contains("d:t:bb"), "{n:?}");
        store.release("d:t:aa").unwrap();
        assert!(!store.is_spent("d:t:aa"));
        assert!(!load_nullifiers(&new).unwrap().contains("d:t:aa"));
        assert!(
            load_nullifiers(&old).unwrap().contains("d:t:aa"),
            "a file serve no longer names is left alone"
        );
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::remove_file(&new);

        // Both or neither: a line the file refuses is not reserved.
        let mut store = NullifierStore::default();
        store
            .open(&format!("{}/missing-dir/store", tmp("store-no-parent")))
            .unwrap();
        let err = store.reserve("d:t:aa").unwrap_err();
        assert!(err.starts_with("open "), "got {err}");
        assert!(!store.is_spent("d:t:aa"));
    }

    // A release and a serve merge are one critical section each: in either
    // order the line leaves memory and the file together, so the merge has
    // no released line to load back.
    #[test]
    fn a_release_and_a_serve_merge_cannot_resurrect_a_line() {
        let path = tmp("release-merge");
        let nul = "d:t:cc";
        let mut store = NullifierStore::default();
        store.open(&path).unwrap();

        assert!(store.reserve(nul).unwrap());
        store.open(&path).unwrap();
        store.release(nul).unwrap();
        assert!(!store.is_spent(nul));
        assert!(!load_nullifiers(&path).unwrap().contains(nul));

        assert!(store.reserve(nul).unwrap());
        store.release(nul).unwrap();
        store.open(&path).unwrap();
        assert!(!store.is_spent(nul));
        assert!(!load_nullifiers(&path).unwrap().contains(nul));
        let _ = std::fs::remove_file(&path);
    }
}

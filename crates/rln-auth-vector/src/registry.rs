//! What a module composes: its schemes × authorisers (verify side) or its
//! signers × claimants (produce side), and the module-method glue.

use crate::authtype::AuthType;
use crate::flow::{produce_flow, verify_flow};
use crate::pieces::{Authoriser, Claimant, Scheme, Signer};
use crate::reason;
use crate::types::{error_reply, ProduceRequest, VerifyRequest};

// OWNERSHIP: an open, heterogeneous plugin set, so boxed trait objects the registry owns for
// the life of the module instance. `Box<dyn Trait>` means `dyn Trait + 'static`: a piece holds
// no borrows (what it borrowed would sit beside the registry in the module, a self-reference).
#[derive(Default)]
pub struct VerifyRegistry {
    schemes: Vec<Box<dyn Scheme>>,
    authorisers: Vec<Box<dyn Authoriser>>,
}

impl VerifyRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn scheme(mut self, s: impl Scheme + 'static) -> Self {
        self.schemes.push(Box::new(s));
        self
    }
    pub fn authoriser(mut self, a: impl Authoriser + 'static) -> Self {
        self.authorisers.push(Box::new(a));
        self
    }

    /// The scheme and authoriser of `t`, if both exist here and compose.
    pub fn resolve(&self, t: &AuthType) -> Result<(&dyn Scheme, &dyn Authoriser), String> {
        let s = self
            .schemes
            .iter()
            .find(|s| s.name() == t.scheme)
            .ok_or_else(|| {
                reason::unknown_composition(t, format!("no scheme '{}' on this module", t.scheme))
            })?;
        let a = self
            .authorisers
            .iter()
            .find(|a| a.name() == t.authoriser)
            .ok_or_else(|| {
                reason::unknown_composition(
                    t,
                    format!("no authoriser '{}' on this module", t.authoriser),
                )
            })?;
        if !a.accepts(&t.scheme) {
            return Err(reason::unknown_composition(
                t,
                format!(
                    "the {} authoriser does not accept the {} scheme",
                    t.authoriser, t.scheme
                ),
            ));
        }
        Ok((s.as_ref(), a.as_ref()))
    }

    /// Every `auth_type` this registry serves, scheme-major.
    pub fn auth_types(&self) -> Vec<String> {
        let mut out = Vec::new();
        for s in &self.schemes {
            for a in &self.authorisers {
                if a.accepts(s.name()) {
                    out.push(AuthType::new(s.name(), a.name()).name());
                }
            }
        }
        out
    }
}

// OWNERSHIP: as for `VerifyRegistry` above.
#[derive(Default)]
pub struct ProduceRegistry {
    signers: Vec<Box<dyn Signer>>,
    claimants: Vec<Box<dyn Claimant>>,
}

impl ProduceRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn signer(mut self, s: impl Signer + 'static) -> Self {
        self.signers.push(Box::new(s));
        self
    }
    pub fn claimant(mut self, c: impl Claimant + 'static) -> Self {
        self.claimants.push(Box::new(c));
        self
    }

    pub fn resolve(&self, t: &AuthType) -> Result<(&dyn Signer, &dyn Claimant), String> {
        let s = self
            .signers
            .iter()
            .find(|s| s.scheme() == t.scheme)
            .ok_or_else(|| {
                reason::unknown_composition(t, format!("no {} signer on this module", t.scheme))
            })?;
        let c = self
            .claimants
            .iter()
            .find(|c| c.authoriser() == t.authoriser)
            .ok_or_else(|| {
                reason::unknown_composition(
                    t,
                    format!("no {} claimant on this module", t.authoriser),
                )
            })?;
        if !c.accepts(&t.scheme) {
            return Err(reason::unknown_composition(
                t,
                format!(
                    "the {} claimant does not accept the {} scheme",
                    t.authoriser, t.scheme
                ),
            ));
        }
        Ok((s.as_ref(), c.as_ref()))
    }

    pub fn auth_types(&self) -> Vec<String> {
        let mut out = Vec::new();
        for s in &self.signers {
            for c in &self.claimants {
                if c.accepts(s.scheme()) {
                    out.push(AuthType::new(s.scheme(), c.authoriser()).name());
                }
            }
        }
        out
    }
}

/// Module-method glue for [`crate::VERIFY_METHOD`]: `args_json` in, reply JSON out.
pub fn dispatch_verify(args_json: &str, r: &VerifyRegistry) -> String {
    let run = || {
        let req: VerifyRequest =
            serde_json::from_str(args_json).map_err(|e| format!("verify_auth args: {e}"))?;
        verify_flow(r, &req)
    };
    match run() {
        Ok(verdict) => {
            serde_json::to_string(&verdict).unwrap_or_else(|e| error_reply(&e.to_string()))
        }
        Err(e) => error_reply(&e),
    }
}

/// Module-method glue for [`crate::PRODUCE_METHOD`]: `args_json` in, reply JSON out.
pub fn dispatch_produce(args_json: &str, r: &ProduceRegistry) -> String {
    let run = || {
        let req: ProduceRequest =
            serde_json::from_str(args_json).map_err(|e| format!("produce_auth args: {e}"))?;
        produce_flow(r, &req)
    };
    match run() {
        Ok(reply) => serde_json::to_string(&reply).unwrap_or_else(|e| error_reply(&e.to_string())),
        Err(e) => error_reply(&e),
    }
}

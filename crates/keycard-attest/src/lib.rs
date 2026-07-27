// Keycard IDENTIFY_CARD attestation verification, vendored verbatim from the
// keycard_rln crate's attest module so the gifter server verifies genuine-card
// attestations with no card-hardware (PCSC) dependency.
// FEATURE: RLN membership gifter keycard attestation verification

pub mod attest;
pub mod error;

// In-process Keycard PC/SC client, vendored from keycard_rln_module's keycard
// submodule so the gifter's card capture has no rln-zone-mono dependency.
// FEATURE: RLN membership gifter keycard capture

pub mod apdu;
pub mod crypto;
mod client;

pub use client::{reader_card_present, Keycard, STEALTH_EXPORT_PATH};

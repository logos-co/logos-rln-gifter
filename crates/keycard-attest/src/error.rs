// Error type for the keycard-rooted RLN identity prototype
// FEATURE: Keycard-rooted RLN identities

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Backend(String),
    InvalidSignature,
    InvalidInput(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Backend(m) => write!(f, "keycard backend error: {m}"),
            Error::InvalidSignature => write!(f, "signature does not verify"),
            Error::InvalidInput(m) => write!(f, "invalid input: {m}"),
        }
    }
}

impl std::error::Error for Error {}

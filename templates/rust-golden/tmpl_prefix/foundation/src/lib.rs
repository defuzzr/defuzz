//! Foundation layer (`foundation/`): shared primitives and error types.
//!
//! Allowed internal dependencies: none (lowest workspace layer).

use std::fmt;

/// Canonical workspace name.
pub const NAME: &str = "tmpl-prefix";

/// Workspace error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// An operation failed with a descriptive message.
    Message(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {}

/// Convenience result alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

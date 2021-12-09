use hex::FromHexError;
use thiserror::Error;

#[derive(Debug, Clone, Copy, Error)]
pub enum EncryptedKeyError {
    #[error("Invalid hashed password string length")]
    InvalidLength,
    #[error("Unsupported prefix in hashed password. Must start with 16:")]
    UnsupportedPrefix,
    #[error("Invalid indicator in hashed password string")]
    InvalidIndicator,
    #[error("Non-hexadecimal input in hashed password string")]
    InvalidCharacter(#[from] FromHexError),
}

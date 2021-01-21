use openssl::error::ErrorStack;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum CryptoError {
  #[error("data encryption failed: {0}")]
  #[allow(dead_code)]
  Encryption(String),

  #[error("data decryption failed: {0}")]
  Decryption(String),
}

impl From<ErrorStack> for CryptoError {
  fn from(e: ErrorStack) -> Self {
    CryptoError::Encryption(e.to_string())
  }
}

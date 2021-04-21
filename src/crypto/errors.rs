use openssl::error::ErrorStack;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
  #[error("data encryption failed: {0}")]
  #[allow(dead_code)]
  Encryption(String),

  #[error("data decryption failed: {0}")]
  Decryption(String),

  #[error("invalid key: {0}")]
  InvalidKey(String),

  #[error("invalid file path: {0}")]
  FilePath(String),

  #[error("openssl error")]
  OpenSSLError { source: openssl::error::ErrorStack },

  #[error("read error")]
  _ReadError { source: std::io::Error },

  #[error("write error")]
  WriteError { source: std::io::Error },

  #[error(transparent)]
  IoError(#[from] std::io::Error),
}

impl From<ErrorStack> for CryptoError {
  fn from(e: ErrorStack) -> Self {
    CryptoError::Encryption(e.to_string())
  }
}

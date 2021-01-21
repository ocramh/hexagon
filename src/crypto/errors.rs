use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum EncrytpError {
  #[error("data encryption failed: {0}")]
  #[allow(dead_code)]
  Encryption(String),

  #[error("data decryption failed: {0}")]
  Decryption(String),
}

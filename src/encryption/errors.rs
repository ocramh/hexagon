use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum EncrytpError {
  #[error("data encryption failed: {0}")]
  Encryption(String),

  #[error("data decryption failed: {0}")]
  Decryption(String),
}

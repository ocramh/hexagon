use super::errors::EncrytpError;
use super::key::Key;

// SymmetricEncryptor defines a set of methods for generating a cypher (key), encrypt
// and decrypt bytes of data
pub trait SymmetricEncryptor {
  // generates a new SymmetricEncryptor with signing key
  fn new_with_key() -> Self;

  // returns the signing key
  fn get_key(&self) -> Key;

  // encrypt content with key
  fn encrypt(&self, content: &[u8]) -> Result<Vec<u8>, EncrytpError>;

  // decrypt content with key
  fn decrypt(&self, content: &[u8]) -> Result<Vec<u8>, EncrytpError>;
}

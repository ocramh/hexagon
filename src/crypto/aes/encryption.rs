use crate::crypto::aes::key::Key;
use crate::crypto::errors::EncrytpError;

// SymmetricEncryptor defines a set of methods for generating a cypher (key), encrypt
// and decrypt bytes of data
pub trait SymmetricEncryptor {
  // generates a 32 bytes random key
  fn gen_random_key(&self) -> Key;

  // encrypt content with key
  fn encrypt(&self, content: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, EncrytpError>;

  // decrypt content with key
  fn decrypt(&self, content: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, EncrytpError>;
}

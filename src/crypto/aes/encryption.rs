use crate::crypto::aes::key::Key;
use crate::crypto::errors::CryptoError;

pub struct CipherBox {
  pub b64_ciphertext: String,
  pub b64_nonce: String,
}

// SymmetricEncryptor defines a set of methods for generating a cypher (key), encrypt
// and decrypt bytes of data
pub trait SymmetricEncryptor {
  // generates a 32 bytes random key
  fn gen_random_key(&self) -> Key;

  // encrypt plaintext with secret key to base 64 encoded ciphertext and nonce
  fn encrypt(&self, content: &[u8], key: &[u8]) -> Result<CipherBox, CryptoError>;

  // decrypt base 64 encoded ciphertext using nonce and secret key
  fn decrypt(&self, cipherbox: &CipherBox, key: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

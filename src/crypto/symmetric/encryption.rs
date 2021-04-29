use crate::crypto::errors::CryptoError;
use crate::crypto::symmetric::key::Key;

pub struct CipherBox {
  pub b64_ciphertext: String,
  pub b64_nonce: String,
}

// SymmetricEncryptor defines a set of methods for generating a secret random key
// and the encryption and decryption of data using a shared secret key and a nonce
pub trait SymmetricEncryptor {
  // generates a 32 bytes random key
  fn gen_random_key(&self) -> Key;

  // encrypt plaintext with secret key to base 64 encoded ciphertext and nonce
  fn encrypt(&self, plaintext: &[u8], key: &[u8]) -> Result<CipherBox, CryptoError>;

  // decrypt base 64 encoded ciphertext using nonce and secret key
  fn decrypt(&self, cipherbox: &CipherBox, key: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

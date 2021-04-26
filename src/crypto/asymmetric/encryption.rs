use crate::crypto::asymmetric::keygen::{KeyPair, KeySize, PrivateKey, PublicKey};
use crate::crypto::errors::CryptoError;

// AsymmetricEncryptor defines a set of methods for generating public/private key
// pairs, encyption using public keys and decryption using private keys
pub trait AsymmetricEncryptor {
  // gen_keypair generates a KeyPair
  fn gen_keypair(&self, size: KeySize) -> Result<KeyPair, CryptoError>;

  // encrypt plaintext with public_key
  fn encrypt(&self, plaintext: &[u8], public_key: &PublicKey) -> Result<Vec<u8>, CryptoError>;

  // deencrypt ciphertext with private_key
  fn decrypt(&self, ciphertext: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>, CryptoError>;
}
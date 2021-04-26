extern crate openssl;

use crate::crypto::asymmetric::encryption::AsymmetricEncryptor;
use crate::crypto::asymmetric::keygen::{KeyGen, KeyPair, KeySize, PrivateKey, PublicKey};
use crate::crypto::errors::CryptoError;
use openssl::rsa::Padding;

pub struct RSACryptor {
  keygen: KeyGen,
}

impl RSACryptor {
  #[allow(dead_code)]
  pub fn new(k: KeyGen) -> RSACryptor {
    RSACryptor { keygen: k }
  }
}

impl AsymmetricEncryptor for RSACryptor {
  // gen_keypair generates a KeyPair
  fn gen_keypair(&self, size: KeySize) -> Result<KeyPair, CryptoError> {
    self.keygen.gen_keypair(Some(size))
  }

  // encrypt plaintext with public_key. If plaintext is larger than public_key size
  // it will return an error
  fn encrypt(&self, plaintext: &[u8], public_key: &PublicKey) -> Result<Vec<u8>, CryptoError> {
    let mut dest_buffer: Vec<u8> = vec![0; public_key.size() as usize];

    if plaintext.len() > dest_buffer.len() {
      return Err(CryptoError::Encryption(format!(
        "plaintext size cannot exceed {} bytes",
        dest_buffer.len()
      )));
    }

    public_key.public_encrypt(plaintext, &mut dest_buffer, Padding::PKCS1)?;

    Ok(dest_buffer)
  }

  // deencrypt ciphertext with private_key
  fn decrypt(&self, ciphertext: &[u8], private_key: &PrivateKey) -> Result<Vec<u8>, CryptoError> {
    let mut dest_buffer: Vec<u8> = vec![0; private_key.size() as usize];

    private_key.private_decrypt(ciphertext, &mut dest_buffer, Padding::PKCS1)?;

    Ok(dest_buffer)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::crypto::asymmetric::keygen::{KeyGen, KeySize};

  #[test]
  fn rsa_encrypt_and_decrypt_with_new_key() -> Result<(), CryptoError> {
    let keygen = KeyGen {};
    let rsa_cyptor = RSACryptor::new(keygen);
    let content = String::from("foobarbaz💖");

    let keys = rsa_cyptor.gen_keypair(KeySize::S2048).unwrap();

    let encrypted = rsa_cyptor
      .encrypt(&content.as_bytes(), &keys.public)
      .unwrap();

    let mut decrypted = rsa_cyptor.decrypt(&encrypted, &keys.private).unwrap();
    decrypted.truncate(content.len());

    assert_eq!(content.as_bytes(), decrypted.as_slice());

    Ok(())
  }

  #[test]
  #[should_panic]
  fn rsa_encrypt_and_decrypt_key_error() {
    let keygen = KeyGen {};
    let rsa_cyptor = RSACryptor::new(keygen);
    let content = String::from("foobarbaz💖");

    let keys = rsa_cyptor.gen_keypair(KeySize::S2048).unwrap();
    let keys2 = rsa_cyptor.gen_keypair(KeySize::S2048).unwrap();

    let encrypted = rsa_cyptor
      .encrypt(&content.as_bytes(), &keys.public)
      .unwrap();

    rsa_cyptor.decrypt(&encrypted, &keys2.private).unwrap();
  }
}

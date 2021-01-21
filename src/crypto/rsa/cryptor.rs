extern crate openssl;

use crate::crypto::errors::CryptoError;
use crate::crypto::rsa::keygen::{BoxResult, KeyGen, KeyPair};
use openssl::rsa::{Padding, Rsa};

pub struct RSACryptor {
  keys: KeyPair,
}

impl RSACryptor {
  #[allow(dead_code)]
  pub fn new(keygen: &KeyGen) -> BoxResult<RSACryptor> {
    let keypair = keygen.new_keypair()?;

    Ok(RSACryptor { keys: keypair })
  }

  #[allow(dead_code)]
  pub fn new_with_keys(privk: Vec<u8>) -> Result<RSACryptor, CryptoError> {
    let privk_from_pem = match Rsa::private_key_from_pem(&privk) {
      Ok(k) => k,
      Err(_) => {
        return Err(CryptoError::Encryption(
          "error generating private key from pem".to_string(),
        ))
      }
    };

    Ok(RSACryptor {
      keys: KeyPair {
        rsa: privk_from_pem,
      },
    })
  }

  // encrypt content using the RSACryptor public key
  #[allow(dead_code)]
  pub fn encrypt(&self, content: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut dest_buffer: Vec<u8> = vec![0; self.keys.rsa.size() as usize];

    self
      .keys
      .rsa
      .public_encrypt(content, &mut dest_buffer, Padding::PKCS1)?;

    Ok(dest_buffer)
  }

  // encrypt content using the RSACryptor private key
  #[allow(dead_code)]
  pub fn decrypt(&self, content: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut dest_buffer: Vec<u8> = vec![0; self.keys.rsa.size() as usize];

    self
      .keys
      .rsa
      .private_decrypt(content, &mut dest_buffer, Padding::PKCS1)?;

    Ok(dest_buffer)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn encrypt_decrypt_bytes() -> BoxResult<()> {
    let rsa_keygen = KeyGen {};
    let rsa_cyptor = RSACryptor::new(&rsa_keygen).unwrap();
    let content = String::from("foobarbaz💖");

    let encrypted = rsa_cyptor.encrypt(&content.as_bytes()).unwrap();

    let mut decrypted = rsa_cyptor.decrypt(&encrypted).unwrap();
    decrypted.truncate(content.len());

    assert_eq!(content.as_bytes(), decrypted.as_slice());

    Ok(())
  }

  #[test]
  fn new_with_keys_error() -> BoxResult<()> {
    let privk = std::vec::Vec::new();
    match RSACryptor::new_with_keys(privk) {
      Ok(_) => panic!("creating RSA keys with an empty vector shouldn't work"),
      Err(e) => assert_eq!(
        e,
        CryptoError::Encryption("error generating private key from pem".to_string())
      ),
    }

    Ok(())
  }
}

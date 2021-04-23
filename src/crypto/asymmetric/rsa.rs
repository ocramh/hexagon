extern crate openssl;

use crate::crypto::asymmetric::encryption::AsymmetricEncryptor;
use crate::crypto::asymmetric::keygen::{KeyGen, KeyPair, PrivateKey, PublicKey};
use crate::crypto::errors::CryptoError;
use openssl::rsa::{Padding, Rsa};

pub struct RSACryptor {
  keys: KeyPair,
}

impl RSACryptor {
  #[allow(dead_code)]
  pub fn new(keygen: &KeyGen) -> Result<RSACryptor, CryptoError> {
    let keypair = keygen.gen_keypair(None)?;

    Ok(RSACryptor { keys: keypair })
  }

  pub fn new_with_keys(pem: Vec<u8>) -> Result<RSACryptor, CryptoError> {
    let privk_from_pem = match Rsa::private_key_from_pem(&pem) {
      Ok(k) => k,
      Err(e) => {
        return Err(CryptoError::Encryption(format!(
          "error generating private key from pem: {}",
          e
        )))
      }
    };

    let pubk_from_pem = match Rsa::public_key_from_pem(&pem) {
      Ok(k) => k,
      Err(e) => {
        return Err(CryptoError::Encryption(format!(
          "error generating private key from pem: {}",
          e
        )))
      }
    };

    Ok(RSACryptor {
      keys: KeyPair {
        private: privk_from_pem,
        public: pubk_from_pem,
      },
    })
  }
}

impl AsymmetricEncryptor for RSACryptor {
  // gen_keypair generates a KeyPair
  fn gen_keypair(&self) -> KeyPair {
    self.keys
  }

  // encrypt plaintext with public_key
  fn encypt(&self, plaintext: &[u8], public_key: PublicKey) -> Result<Vec<u8>, CryptoError> {
    let mut dest_buffer: Vec<u8> = vec![0; self.keys.private.size() as usize];
    public_key.public_encrypt(plaintext, &mut dest_buffer, Padding::PKCS1)?;

    Ok(dest_buffer)
  }

  // deencrypt ciphertext with private_key
  fn decrypt(&self, ciphertext: &[u8], private_key: PrivateKey) -> Result<Vec<u8>, CryptoError> {
    let mut dest_buffer: Vec<u8> = vec![0; self.keys.private.size() as usize];
    private_key.private_decrypt(ciphertext, &mut dest_buffer, Padding::PKCS1)?;

    Ok(dest_buffer)
  }
}

// encrypt content using the public key.If plaintext is larger than public_key size
// it will return an error
// pub fn encrypt(&self, content: &[u8]) -> Result<Vec<u8>, CryptoError> {
//   let mut dest_buffer: Vec<u8> = vec![0; self.keys.rsa.size() as usize];

//   self
//     .keys
//     .rsa
//     .public_encrypt(content, &mut dest_buffer, Padding::PKCS1)?;

//   Ok(dest_buffer)
// }

// // encrypt content using the RSACryptor private key
// #[allow(dead_code)]
// pub fn decrypt(&self, content: &[u8]) -> Result<Vec<u8>, CryptoError> {
//   let mut dest_buffer: Vec<u8> = vec![0; self.keys.rsa.size() as usize];

//   self
//     .keys
//     .rsa
//     .private_decrypt(content, &mut dest_buffer, Padding::PKCS1)?;

//   Ok(dest_buffer)
// }

#[cfg(test)]
mod tests {
  use super::*;
  use crate::crypto::asymmetric::keygen::{KeyGen, KeySize};

  #[test]
  fn encrypt_decrypt_with_new_key() -> Result<(), CryptoError> {
    let keygen = KeyGen {};
    let rsa_cyptor = RSACryptor::new(&keygen).unwrap();
    let content = String::from("foobarbaz💖");

    let encrypted = rsa_cyptor.encrypt(&content.as_bytes()).unwrap();

    let mut decrypted = rsa_cyptor.decrypt(&encrypted).unwrap();
    decrypted.truncate(content.len());

    assert_eq!(content.as_bytes(), decrypted.as_slice());

    Ok(())
  }

  #[test]
  fn encrypt_decrypt_with_existing_key() -> Result<(), CryptoError> {
    let keygen = KeyGen::new();
    let key = keygen.gen_keypair(Some(KeySize::S2048)).unwrap();
    let pem = key.rsa.private_key_to_pem().unwrap();
    let rsa_cyptor = RSACryptor::new_with_keys(pem).unwrap();

    let content = String::from("foobarbaz💖");
    let encrypted = rsa_cyptor.encrypt(&content.as_bytes()).unwrap();

    let mut decrypted = rsa_cyptor.decrypt(&encrypted).unwrap();
    decrypted.truncate(content.len());

    assert_eq!(content.as_bytes(), decrypted.as_slice());

    Ok(())
  }

  #[test]
  #[should_panic(expected = "error generating private key from pem")]
  fn new_with_keys_error() {
    let privk = std::vec::Vec::new();
    RSACryptor::new_with_keys(privk).unwrap();
  }
}

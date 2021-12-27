extern crate rand;

use crate::crypto::errors::CryptoError;
use crate::crypto::symmetric::encryption::{CipherBox, SymmetricEncryptor};
use crate::crypto::symmetric::key::Key;
use rand::{thread_rng, Rng};
use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::Nonce;

// XsalsaPoly is an implementation of the SymmetricEncryptor based on the
// XSalsa20Poly1305 authenticated encryption
pub struct XsalsaPoly {}

impl XsalsaPoly {
  pub fn new() -> XsalsaPoly {
    XsalsaPoly {}
  }
}

impl SymmetricEncryptor for XsalsaPoly {
  fn gen_random_key(&self) -> Key {
    let mut rng = thread_rng();
    Key(rng.gen())
  }

  fn encrypt(&self, plaintext: &[u8], secret: &[u8]) -> Result<CipherBox, CryptoError> {
    let keyhash = hash::sha256::hash(&secret);

    let key = secretbox::Key(keyhash.0);
    let nonce = secretbox::gen_nonce();

    let ciphertext = secretbox::seal(plaintext, &nonce, &key);

    Ok(CipherBox {
      b64_ciphertext: base64::encode(ciphertext),
      b64_nonce: base64::encode(nonce),
    })
  }

  fn decrypt(&self, cipherbox: &CipherBox, secret: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let keyhash = hash::sha256::hash(&secret);
    let key = secretbox::Key(keyhash.0);

    let ciphertext = match base64::decode(&cipherbox.b64_ciphertext) {
      Ok(v) => v,
      Err(e) => {
        return Err(CryptoError::Decryption(format!(
          "Invalid base46 ciphertext: {}",
          e
        )))
      }
    };

    let n = match base64::decode(&cipherbox.b64_nonce) {
      Ok(v) => v,
      Err(e) => {
        return Err(CryptoError::Decryption(format!(
          "Invalid base46 nonce: {}",
          e
        )))
      }
    };

    let nonce = match Nonce::from_slice(&n) {
      Some(v) => v,
      None => {
        return Err(CryptoError::Decryption(
          "invalid decryption nonce".to_string(),
        ))
      }
    };

    let decoded = match secretbox::open(&ciphertext, &nonce, &key) {
      Ok(v) => v,
      Err(e) => return Err(CryptoError::Decryption(format!("{:?}", e))),
    };

    Ok(decoded)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn encrypt_decrypt_ok() -> Result<(), CryptoError> {
    let key = "my-secret-key";
    let plaintext = b"some data to encypt";

    let cryptor = XsalsaPoly::new();

    let encrypted_box = cryptor.encrypt(plaintext, key.as_bytes())?;
    let decrypted = cryptor.decrypt(&encrypted_box, key.as_bytes())?;

    assert_eq!(plaintext, &decrypted[..]);
    Ok(())
  }

  #[test]
  #[should_panic(expected = "Invalid base46 ciphertext:")]
  fn decrypt_plaintext_base64_decode_error() {
    let plaintext = "some data to encypt".to_string();
    let key = "my-secret-key";
    let nonce = "my-nonce".to_string();
    let cryptor: XsalsaPoly = XsalsaPoly::new();

    cryptor
      .decrypt(
        &CipherBox {
          b64_ciphertext: plaintext,
          b64_nonce: nonce,
        },
        key.as_bytes(),
      )
      .unwrap();
  }

  #[test]
  #[should_panic(expected = "Invalid base46 nonce:")]
  fn decrypt_nonce_base64_decode_error() {
    let plaintext = base64::encode(b"some data to encypt");
    let key = "my-secret-key";
    let nonce = "my-nonce".to_string();

    let cryptor: XsalsaPoly = XsalsaPoly::new();

    cryptor
      .decrypt(
        &CipherBox {
          b64_ciphertext: plaintext,
          b64_nonce: nonce,
        },
        key.as_bytes(),
      )
      .unwrap();
  }
}

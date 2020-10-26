extern crate tindercrypt;

use rand::{thread_rng, Rng};
use tindercrypt::cryptors::RingCryptor;

use super::encryption::SymmetricEncryptor;
use super::errors::EncrytpError;
use super::key::Key;

pub struct Cryptor<'a> {
  key: Key,
  cryptor: RingCryptor<'a>,
}

pub fn new<'b>() -> Cryptor<'b> {
  let mut rng = thread_rng();

  Cryptor {
    key: Key(rng.gen()),
    cryptor: RingCryptor::new(),
  }
}

impl<'a> SymmetricEncryptor for Cryptor<'a> {
  fn new_with_key() -> Cryptor<'a> {
    new()
  }

  fn get_key(&self) -> Key {
    self.key.clone()
  }

  fn encrypt(&self, content: &[u8]) -> Result<Vec<u8>, EncrytpError> {
    match self.cryptor.seal_with_key(&self.key.0, content) {
      Ok(v) => Ok(v),
      Err(e) => Err(EncrytpError::Encryption(e.to_string())),
    }
  }

  fn decrypt(&self, content: &[u8]) -> Result<Vec<u8>, EncrytpError> {
    match self.cryptor.open(&self.key.0, content) {
      Ok(v) => Ok(v),
      Err(e) => Err(EncrytpError::Decryption(e.to_string())),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn get_key() {
    let cypher = thread_rng().gen();

    let c = Cryptor {
      key: Key(cypher),
      cryptor: RingCryptor::new(),
    };

    assert_eq!(c.get_key(), Key(cypher));
  }

  #[test]
  fn encrypt_decrypt_bytes() -> Result<(), EncrytpError> {
    let cryptor: Cryptor = SymmetricEncryptor::new_with_key();
    let content = String::from("foobarbaz💖");

    let encrypted = cryptor.encrypt(content.as_bytes())?;
    let decrypted = cryptor.decrypt(encrypted.as_slice())?;

    assert_eq!(content, String::from_utf8(decrypted).unwrap());
    Ok(())
  }

  #[test]
  fn decrypt_error() {
    let cryptor: Cryptor = SymmetricEncryptor::new_with_key();
    let content = String::from("foobar");
    match cryptor.decrypt(content.as_bytes()) {
      Ok(_) => assert!(false, "should not be ok"),
      Err(_) => assert!(true),
    }
  }
}

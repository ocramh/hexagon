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

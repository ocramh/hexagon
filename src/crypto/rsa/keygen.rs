extern crate openssl;

use openssl::rsa::Rsa;
use std::error::Error;

const KEY_SIZE: u32 = 4096;

pub type BoxResult<T> = Result<T, Box<dyn Error>>;

pub struct KeyGen {}

pub struct KeyPair {
  pub publkey: Vec<u8>,
  pub privkey: Vec<u8>,
}

impl KeyGen {
  pub fn new_keypair(&self) -> BoxResult<KeyPair> {
    let rsa = Rsa::generate(KEY_SIZE).unwrap();

    let priv_key: Vec<u8> = rsa.private_key_to_pem().unwrap();
    let publ_key: Vec<u8> = rsa.public_key_to_pem().unwrap();

    Ok(KeyPair {
      publkey: publ_key,
      privkey: priv_key,
    })
  }

  #[allow(dead_code)]
  pub fn save_keys_to_file(&self, _key_name: String) {}
}

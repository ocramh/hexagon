extern crate openssl;

use openssl::rsa::Rsa;
use std::error::Error;
use std::str;

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

    println!("private k: {}", str::from_utf8(&priv_key).unwrap());
    println!("public k: {}", str::from_utf8(&publ_key).unwrap());

    Ok(KeyPair {
      publkey: publ_key,
      privkey: priv_key,
    })
  }

  pub fn save_keys_to_file(&self, key_name: String) {}
}

extern crate openssl;

use super::keygen::{BoxResult, KeyGen, KeyPair};

pub struct Cryptor {
  keys: KeyPair,
}

impl Cryptor {
  pub fn new(keygen: &KeyGen) -> BoxResult<Self> {
    let keypair = keygen.new_keypair()?;

    Ok(Cryptor { keys: keypair })
  }

  #[allow(dead_code)]
  pub fn new_with_keys(pubk: Vec<u8>, privk: Vec<u8>) -> Self {
    Cryptor {
      keys: KeyPair {
        publkey: pubk,
        privkey: privk,
      },
    }
  }

  pub fn encrypt(&self, _content: &[u8]) -> BoxResult<Vec<u8>> {
    println!("RSA encryption happens here");
    Ok(Vec::new())
  }

  #[allow(dead_code)]
  pub fn decrypt(&self, _content: &[u8]) -> BoxResult<Vec<u8>> {
    println!("RSA decryption happens here");
    Ok(Vec::new())
  }
}

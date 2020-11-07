extern crate openssl;

use crate::crypto::rsa::keygen::{BoxResult, KeyGen, KeyPair};
use openssl::rsa::{Padding, Rsa};
use std::str;

pub struct Cryptor {
  keys: KeyPair,
}

impl Cryptor {
  pub fn new(keygen: &KeyGen) -> BoxResult<Self> {
    let keypair = keygen.new_keypair()?;

    // keygen.save_keys_to_file(&keypair.rsa, &String::from("."))?;

    Ok(Cryptor { keys: keypair })
  }

  #[allow(dead_code)]
  pub fn new_with_keys(privk: Vec<u8>) -> BoxResult<Self> {
    let privk_from_pem = Rsa::private_key_from_pem(&privk)?;

    Ok(Cryptor {
      keys: KeyPair {
        rsa: privk_from_pem,
      },
    })
  }

  pub fn encrypt(&self, content: &[u8]) -> BoxResult<Vec<u8>> {
    let mut dest_buffer: Vec<u8> = vec![0; self.keys.rsa.size() as usize];
    self
      .keys
      .rsa
      .public_encrypt(content, &mut dest_buffer, Padding::PKCS1)?;

    Ok(dest_buffer)
  }

  pub fn decrypt(&self, content: &[u8]) -> BoxResult<Vec<u8>> {
    let mut dest_buffer: Vec<u8> = vec![0; self.keys.rsa.size() as usize];
    self
      .keys
      .rsa
      .private_decrypt(content, &mut dest_buffer, Padding::PKCS1)?;

    println!("Decrypted: {}", str::from_utf8(&dest_buffer).unwrap());

    Ok(dest_buffer)
  }
}

#[test]
fn encrypt_decrypt_bytes() -> BoxResult<()> {
  let rsa_keygen = KeyGen {};
  let rsa_cyptor = Cryptor::new(&rsa_keygen).unwrap();
  let content = String::from("A quick brown fox jumps over the lazy dog");

  let encrypted = rsa_cyptor.encrypt(&content.as_bytes()).unwrap();

  let mut decrypted = rsa_cyptor.decrypt(&encrypted).unwrap();
  decrypted.truncate(content.len());

  assert_eq!(content.as_bytes(), decrypted.as_slice());

  Ok(())
}

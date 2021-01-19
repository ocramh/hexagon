extern crate crypto as cryp;
extern crate rand;

use crate::crypto::aes::encryption::SymmetricEncryptor;
use crate::crypto::aes::key::Key;
use crate::crypto::errors::EncrytpError;
use cryp::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use cryp::{aes, blockmodes, buffer, symmetriccipher};
use rand::{thread_rng, OsRng, Rng};

pub struct AESCryptor {
  key: Key,
}

impl AESCryptor {
  pub fn new() -> AESCryptor {
    let mut rng = thread_rng();

    AESCryptor {
      key: Key(rng.gen()),
    }
  }
}

impl SymmetricEncryptor for AESCryptor {
  fn gen_random_key(&self) -> Key {
    let mut rng = thread_rng();
    Key(rng.gen())
  }

  // encrypts content using an AES-CTR cipher
  fn encrypt(&self, content: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncrytpError> {
    let mut kkey: [u8; 32] = [0; 32];
    let mut iiv: [u8; 16] = [0; 16];
    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut kkey);
    rng.fill_bytes(&mut iiv);

    println!("build encryptor");
    let mut encryptor = aes::ctr(aes::KeySize::KeySize128, &kkey, &iiv);

    println!("setting capacity");
    let mut output_cypher = Vec::with_capacity(content.len());
    output_cypher.resize(content.len(), 0);

    println!(
      "input len: {}. output len: {}",
      content.len(),
      output_cypher.len()
    );
    encryptor.process(content, &mut output_cypher);

    println!("putputting it");
    Ok(output_cypher)
  }

  fn decrypt(&self, _content: &[u8], _key: &[u8], _iv: &[u8]) -> Result<Vec<u8>, EncrytpError> {
    let output_vec = Vec::<u8>::new();

    Ok(output_vec)
  }
}

/*
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
*/

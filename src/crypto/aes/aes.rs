extern crate crypto as cryp;
extern crate rand;

use crate::crypto::aes::encryption::SymmetricEncryptor;
use crate::crypto::aes::key::Key;
use crate::crypto::errors::CryptoError;
use cryp::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use cryp::symmetriccipher::Decryptor;
use cryp::{aes, buffer};
use rand::{thread_rng, Rng};

pub struct AESCryptor {}

impl AESCryptor {
  pub fn new() -> AESCryptor {
    AESCryptor {}
  }
}

impl SymmetricEncryptor for AESCryptor {
  fn gen_random_key(&self) -> Key {
    let mut rng = thread_rng();
    Key(rng.gen())
  }

  // encrypts content using an AES-CTR cipher
  fn encrypt(&self, content: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut encryptor = aes::ctr(aes::KeySize::KeySize128, &key, &iv);

    let mut output_cypher = Vec::with_capacity(content.len());
    output_cypher.resize(content.len(), 0);
    encryptor.process(content, &mut output_cypher);
    Ok(output_cypher)
  }

  // decrypts a cipher using the encrytpion key and the initialization vector provided
  fn decrypt(&self, cypher: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut decryptor = aes::ctr(aes::KeySize::KeySize128, &key, &iv);

    let mut output = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(cypher);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
      let res = match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
        Ok(v) => v,
        Err(e) => return Err(CryptoError::Decryption(format!("{:?}", e))),
      };

      output.extend(
        write_buffer
          .take_read_buffer()
          .take_remaining()
          .iter()
          .map(|&i| i),
      );
      match res {
        BufferResult::BufferUnderflow => break,
        BufferResult::BufferOverflow => {}
      }
    }

    Ok(output)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::OsRng;

  #[test]
  fn encrypt_decrypt_bytes() -> Result<(), CryptoError> {
    let cryptor: AESCryptor = AESCryptor::new();
    let content = String::from("foobarbaz💖");
    let key = cryptor.gen_random_key();
    let mut iv: [u8; 16] = [0; 16];
    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut iv);

    let encrypted = cryptor.encrypt(content.as_bytes(), &key.0, &iv)?;
    let decrypted = cryptor.decrypt(encrypted.as_slice(), &key.0, &iv)?;

    assert_eq!(content, String::from_utf8(decrypted).unwrap());
    Ok(())
  }

  #[test]
  fn decrypt_error() {
    let cryptor: AESCryptor = AESCryptor::new();
    let content = "foobarbaz💖".to_string();

    let key = cryptor.gen_random_key();
    let mut iv: [u8; 16] = [0; 16];
    let mut rng = OsRng::new().ok().unwrap();
    rng.fill_bytes(&mut iv);

    let decrypted = cryptor.decrypt(content.as_bytes(), &key.0, &iv).unwrap();

    assert_ne!(decrypted, content.as_bytes());
  }
}

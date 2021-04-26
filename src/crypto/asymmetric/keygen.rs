extern crate openssl;

use crate::crypto::errors::CryptoError;
use openssl::pkey::Private;
use openssl::pkey::Public;
use openssl::rsa::Rsa;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

pub const DEFAULT_KEY_NAME: &str = "id_rsa";

#[repr(u32)]
pub enum KeySize {
  S1024 = 1024,
  S2048 = 2048,
  S4096 = 4096,
}

impl KeySize {
  pub fn keysize_from_str(val: &str) -> Result<Self, CryptoError> {
    let ks = match val {
      "1024" => KeySize::S1024,
      "2048" => KeySize::S2048,
      "4096" => KeySize::S4096,
      _ => {
        return Err(CryptoError::InvalidKey(
          "invalid key size. Allowed values are 1024, 2048, 4096".to_string(),
        ))
      }
    };

    Ok(ks)
  }
}

pub type PrivateKey = Rsa<Private>;
pub type PublicKey = Rsa<Public>;
pub struct KeyPair {
  pub private: PrivateKey,
  pub public: PublicKey,
}

pub struct KeyGen {}

impl KeyGen {
  pub fn new() -> Self {
    KeyGen {}
  }

  pub fn gen_keypair(&self, size: Option<KeySize>) -> Result<KeyPair, CryptoError> {
    let keysize = match size {
      Some(v) => v,
      None => KeySize::S2048,
    };

    let rsa = Rsa::generate(keysize as u32)?;
    let modulo = rsa.n().to_owned().unwrap();
    let exponent = rsa.e().to_owned().unwrap();
    let derived_pubkey = Rsa::from_public_components(modulo, exponent).unwrap();

    Ok(KeyPair {
      private: rsa,
      public: derived_pubkey,
    })
  }

  #[allow(dead_code)]
  pub fn save_keys_to_file(
    &self,
    key: &Rsa<Private>,
    dest_path: &str,
  ) -> Result<bool, CryptoError> {
    if dest_path.is_empty() {
      return Err(CryptoError::FilePath(
        "destination path cannot be empty".to_string(),
      ));
    }

    let mut save_to = Path::new(dest_path).to_path_buf();
    if save_to.is_dir() {
      save_to = save_to.join(DEFAULT_KEY_NAME);
    }

    let priv_u8 = key
      .private_key_to_pem()
      .map_err(|source| CryptoError::OpenSSLError { source })?;

    let pub_u8 = key
      .public_key_to_pem()
      .map_err(|source| CryptoError::OpenSSLError { source })?;

    // error will automatically be wrapped into CryptoError::IoError
    let mut priv_file = File::create(&save_to)?;

    // error will automatically be wrapped into CryptoError::IoError
    let mut pub_file = File::create(&save_to.with_extension("pub"))?;

    priv_file
      .write_all(&priv_u8)
      .map_err(|source| CryptoError::WriteError { source })?;

    pub_file
      .write_all(&pub_u8)
      .map_err(|source| CryptoError::WriteError { source })?;

    Ok(true)
  }
}

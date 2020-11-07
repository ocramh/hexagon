extern crate openssl;

use crate::filesys::errors::FsError;
use anyhow::{Context, Result};
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

const KEY_SIZE: u32 = 4096;
const DEFAULT_KEY_NAME: &str = "id_rsa";

pub type BoxResult<T> = Result<T, Box<dyn Error>>;

pub struct KeyPair {
  pub rsa: Rsa<Private>,
}

pub struct KeyGen {}

impl KeyGen {
  pub fn new_keypair(&self) -> BoxResult<KeyPair> {
    let rsa = Rsa::generate(KEY_SIZE)?;
    Ok(KeyPair { rsa })
  }

  #[allow(dead_code)]
  pub fn save_keys_to_file(&self, key: &Rsa<Private>, dest_path: &String) -> BoxResult<bool> {
    if dest_path.is_empty() {
      return Err(Box::new(FsError::InvalidPath(
        "destination path cannot be empty".into(),
      )));
    }

    let mut save_to = Path::new(dest_path).to_path_buf();
    if save_to.is_dir() {
      save_to = save_to.join(DEFAULT_KEY_NAME);
    }

    let priv_u8 = key.private_key_to_pem()?;
    let pub_u8 = key.public_key_to_pem()?;

    let mut priv_file =
      File::create(&save_to).context(format!("error creating file {}", save_to.display()))?;
    let mut pub_file = File::create(&save_to.with_extension("pub"))
      .context(format!("error creating file {}", save_to.display()))?;

    priv_file.write_all(&priv_u8)?;
    pub_file.write_all(&pub_u8)?;

    Ok(true)
  }
}

// extern crate crypto;
extern crate rand;
extern crate tindercrypt;

use anyhow::{Context, Result};
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

mod encryption;
use encryption::aes;
use encryption::encryption::SymmetricEncryptor;

fn main() -> Result<()> {
  let cryptor: aes::Cryptor = SymmetricEncryptor::new_with_key();

  let file_path = Path::new("test_file.txt");
  let mut file =
    File::create(&file_path).context(format!("error creating file {}", file_path.display()))?;

  let content = "the secret content".as_bytes();

  let cyphertext = cryptor
    .encrypt(&content)
    .context("error  encrypting file")?;

  match file.write_all(&cyphertext) {
    Ok(()) => println!("file written"),
    Err(_) => println!("file not written"),
  };

  let buf = match fs::read(file_path) {
    Ok(v) => v,
    Err(e) => panic!("error reading from file: {}", e),
  };

  let content = cryptor.decrypt(buf.as_slice())?;
  println!("{}", String::from_utf8_lossy(content.as_slice()));
  Ok(())
}

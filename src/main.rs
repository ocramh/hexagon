// extern crate crypto;
extern crate rand;

use anyhow::Result;
// use std::fs::File;
// use std::io::prelude::*;
// use std::path::Path;

mod cli;
mod crypto;
mod filesys;
use crate::cli::tasks;
// use crate::crypto::aes::aes;
// use crate::crypto::aes::encryption::SymmetricEncryptor;

fn main() -> Result<()> {
  tasks::run();

  // let aes_cryptor: aes::AESCryptor = aes::AESCryptor::new();

  // let file_path = Path::new("test_file.txt");
  // let mut file =
  //   File::create(&file_path).context(format!("error creating file {}", file_path.display()))?;

  // let content = "the secret content".as_bytes();

  // let cyphertext = aes_cryptor
  //   .encrypt(&content, &[1, 2, 3], &[4, 5, 6])
  //   .context("error  encrypting file")?;

  // match file.write_all(&cyphertext) {
  //   Ok(()) => println!("file written"),
  //   Err(_) => println!("file not written"),
  // };

  // let buf = match fs::read(file_path) {
  //   Ok(v) => v,
  //   Err(e) => panic!("error reading from file: {}", e),
  // };

  // let content = aes_cryptor.decrypt(buf.as_slice())?;
  // println!("{}", String::from_utf8_lossy(content.as_slice()));
  Ok(())
}

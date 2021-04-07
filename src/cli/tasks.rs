use crate::crypto::aes::aes::AESCryptor;
use crate::crypto::aes::encryption::SymmetricEncryptor;
use crate::crypto::rsa::keygen;
use clap::{load_yaml, App};
use rand::distributions::Alphanumeric;
use rand::Rng;

pub fn run() {
  let yaml = load_yaml!("cli.yaml");
  let matches = App::from(yaml).get_matches();

  if let Some(ref _matches) = matches.subcommand_matches("keygen") {
    return run_keygen_cmd(matches);
  }

  if let Some(ref _matches) = matches.subcommand_matches("encrypt") {
    return run_encrypt_cmd(matches);
  }

  if let Some(ref _matches) = matches.subcommand_matches("decrypt") {
    println!("do asymmetric encryption");
  }
}

fn run_keygen_cmd(args: clap::ArgMatches) {
  let matches = args.subcommand_matches("keygen").unwrap();
  let size = matches.value_of("size").unwrap();
  let dest = matches.value_of("destination").unwrap();

  let keysize = keygen::KeySize::keysize_from_str(size).unwrap();
  let keygen = keygen::KeyGen::new();
  let keypair = keygen.gen_keypair(Some(keysize)).unwrap();

  match keygen.save_keys_to_file(&keypair.rsa, dest) {
    Ok(_) => println!(
      "==> key pair {argument} and {argument}.pub saved at {dest}",
      argument = keygen::DEFAULT_KEY_NAME,
      dest = dest
    ),
    Err(e) => println!("==> error saving key pair {}", e),
  }
}

fn run_encrypt_cmd(args: clap::ArgMatches) {
  let input = match args.value_of("input") {
    Some(v) => v,
    None => panic!("input cannot be empty"),
  };

  let matches = args.subcommand_matches("encrypt").unwrap();
  let enc_type = matches.value_of("type").unwrap();
  let enc_dest = matches.value_of("output").unwrap();

  match enc_type {
    "symmetric" => {
      let secret = matches.value_of("secret").unwrap();
      let rng = rand::thread_rng();

      let iv: String = rng
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

      let cyptor = AESCryptor::new();

      match cyptor.encrypt(input.as_bytes(), secret.as_bytes(), iv.as_bytes()) {
        Ok(val) => println!("{}. init vector: {}", String::from_utf8_lossy(&val), iv),
        Err(e) => println!("==> error encypting input {}", e),
      }
    }
    "asymmetric" => {
      let pub_key = matches.value_of("key").unwrap();
      println!(
        "==> do asymmetric encryption. input: {:?}, secret: {}, output: {}",
        input, pub_key, enc_dest
      );
    }
    _ => println!("==> invalid encryption type. Possible values are symmetric or asymmetric"),
  }
}

use crate::crypto::aes::aes::AESCryptor;
use crate::crypto::aes::encryption::{CipherBox, SymmetricEncryptor};
use crate::crypto::rsa::keygen;
use clap::{load_yaml, App};
extern crate base64;

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
    return run_decrypt_cmd(matches);
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

      let cyptor = AESCryptor::new();

      let encrypt_box = match cyptor.encrypt(input.as_bytes(), secret.as_bytes()) {
        Ok(val) => val,
        Err(e) => panic!(e),
      };

      println!(
        "ciphertext: {}, nonce: {}",
        &encrypt_box.b64_ciphertext, &encrypt_box.b64_nonce
      );

      let decri = match cyptor.decrypt(&encrypt_box, secret.as_bytes()) {
        Ok(val) => val,
        Err(e) => {
          println!("{}", e);
          panic!("some error");
        }
      };

      println!("decripted: {}", std::str::from_utf8(&decri).unwrap());
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

fn run_decrypt_cmd(args: clap::ArgMatches) {
  let base64_input = match args.value_of("ciphertext") {
    Some(v) => v,
    None => panic!("input cannot be empty"),
  };

  let base64_nonce = match args.value_of("nonce") {
    Some(v) => v,
    None => panic!("input cannot be empty"),
  };

  let matches = args.subcommand_matches("decrypt").unwrap();
  let enc_type = matches.value_of("type").unwrap();

  match enc_type {
    "symmetric" => {
      let secret = matches.value_of("secret").unwrap();
      // let nonce = matches.value_of("nonce").unwrap();

      let cyptor = AESCryptor::new();

      match cyptor.decrypt(
        &CipherBox {
          b64_ciphertext: base64_input.to_string(),
          b64_nonce: base64_nonce.to_string(),
        },
        secret.as_bytes(),
      ) {
        Ok(val) => println!("{}", String::from_utf8(val).unwrap()),
        Err(e) => println!("==> error decrypting input {}", e),
      }
    }
    "asymmetric" => {}
    _ => println!("==> invalid decryption type. Possible values are symmetric or asymmetric"),
  };
}

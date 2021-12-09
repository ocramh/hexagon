use crate::crypto::asymmetric::encryption::AsymmetricEncryptor;
use crate::crypto::asymmetric::keygen;
use crate::crypto::asymmetric::rsa::RSACryptor;
use crate::crypto::symmetric::encryption::{CipherBox, SymmetricEncryptor};
use crate::crypto::symmetric::xsalsapoly::XsalsaPoly;
use openssl::rsa::Rsa;
use std::fs;
use std::path::Path;
extern crate base64;
extern crate clap;

pub fn run_encrypt_cmd(args: &clap::ArgMatches) {
  let input = match args.value_of("input") {
    Some(v) => v,
    None => {
      eprintln!("input cannot be empty");
      std::process::exit(1);
    }
  };

  let enc_type = args.value_of("type").unwrap();

  match enc_type {
    "symmetric" => {
      let secret = args.value_of("secret").unwrap();
      let cryptor = XsalsaPoly::new();
      let encrypt_box = match cryptor.encrypt(input.as_bytes(), secret.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
          eprintln!("{}", e);
          std::process::exit(1);
        }
      };

      println!(
        "ciphertext: {}, nonce: {}",
        &encrypt_box.b64_ciphertext, &encrypt_box.b64_nonce
      );
    }
    "asymmetric" => {
      let key_path = args.value_of("key").unwrap();
      let key_content = match fs::read(Path::new(key_path)) {
        Ok(v) => v,
        Err(e) => {
          eprintln!("{}", e);
          std::process::exit(1);
        }
      };

      let cryptor = RSACryptor::new(keygen::KeyGen::new());
      let public_key = match Rsa::public_key_from_pem(&key_content) {
        Ok(v) => v,
        Err(e) => {
          eprintln!("{}", e);
          std::process::exit(1);
        }
      };

      let res = match cryptor.encrypt(input.as_bytes(), &public_key) {
        Ok(v) => v,
        Err(e) => {
          eprintln!("{}", e);
          std::process::exit(1);
        }
      };

      println!("{:?}", res);
    }
    _ => println!("==> invalid encryption type. Possible values are symmetric or asymmetric"),
  }
}

pub fn run_keygen_cmd(args: &clap::ArgMatches) {
  let size = args.value_of("size").unwrap();
  let dest = args.value_of("destination").unwrap();

  let keysize = match keygen::KeySize::keysize_from_str(size) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("{}", e);
      std::process::exit(1);
    }
  };

  let keygen = keygen::KeyGen::new();
  let keypair = match keygen.gen_keypair(Some(keysize)) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("{}", e);
      std::process::exit(1);
    }
  };

  match keygen.save_keys_to_file(&keypair.private, dest) {
    Ok(_) => println!(
      "==> key pair {argument} and {argument}.pub saved at {dest}",
      argument = keygen::DEFAULT_KEY_NAME,
      dest = dest
    ),
    Err(e) => println!("==> error saving key pair {}", e),
  }
}

pub fn run_decrypt_cmd(args: &clap::ArgMatches) {
  let enc_type = args.value_of("type").unwrap();
  let input = match args.value_of("input") {
    Some(v) => v,
    None => {
      eprintln!("input cannot be empty");
      std::process::exit(1);
    }
  };

  match enc_type {
    "symmetric" => {
      let base64_nonce = match args.value_of("nonce") {
        Some(v) => v,
        None => {
          eprintln!("nonce cannot be empty");
          std::process::exit(1);
        }
      };
      let secret = args.value_of("secret").unwrap();

      symmetric_decryption(input, secret, base64_nonce);
    }
    "asymmetric" => {
      let key_path = args.value_of("key").unwrap();
      let key_content = match fs::read(Path::new(key_path)) {
        Ok(v) => v,
        Err(e) => {
          eprintln!("{}", e);
          std::process::exit(1);
        }
      };

      asymmetric_decryption(input, key_content);
    }
    _ => println!("==> invalid decryption type. Possible values are symmetric or asymmetric"),
  };
}

fn symmetric_decryption(b64_ciphertext: &str, b64_secret: &str, b64_nonce: &str) {
  let cyptor = XsalsaPoly::new();

  match cyptor.decrypt(
    &CipherBox {
      b64_ciphertext: b64_ciphertext.to_string(),
      b64_nonce: b64_nonce.to_string(),
    },
    b64_secret.as_bytes(),
  ) {
    Ok(val) => println!("{}", String::from_utf8(val).unwrap()),
    Err(e) => {
      eprintln!("{}", e);
      std::process::exit(1);
    }
  }
}

fn asymmetric_decryption(ciphertext: &str, key_content: Vec<u8>) {
  let cryptor = RSACryptor::new(keygen::KeyGen::new());
  let priv_key = match Rsa::private_key_from_pem(&key_content) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("{}", e);
      std::process::exit(1);
    }
  };

  match cryptor.decrypt(&ciphertext, &priv_key) {
    Ok(val) => println!("{}", String::from_utf8(val).unwrap()),
    Err(e) => {
      eprintln!("{}", e);
      std::process::exit(1);
    }
  };
}

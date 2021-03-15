use crate::crypto::rsa::keygen;
use clap::{load_yaml, App};

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

  println!("==> generating rsa keypair of size {:?}", size);

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
  let input = args.value_of("input");
  if input.is_none() {
    panic!("input cannot be empty");
  }

  let matches = args.subcommand_matches("encrypt").unwrap();
  let enc_type = matches.value_of("type").unwrap();
  let enc_dest = matches.value_of("output").unwrap();

  match enc_type {
    "symmetric" => {
      let secret = matches.value_of("secret").unwrap();
      println!(
        "==> do symmetric encryption. input: {:?}, secret: {}, output: {}",
        input, secret, enc_dest
      );
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

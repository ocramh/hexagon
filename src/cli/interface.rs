use crate::crypto::rsa::keygen;
use clap::{load_yaml, App};

pub fn cli() {
  let yaml = load_yaml!("cli.yaml");
  let matches = App::from(yaml).get_matches();

  if let Some(ref _matches) = matches.subcommand_matches("keygen") {
    return run_keygen_cmd(matches);
  }

  if let Some(ref _matches) = matches.subcommand_matches("asymmetric") {
    println!("do asymmetric encryption");
  }

  if let Some(ref matches) = matches.subcommand_matches("test") {
    if matches.is_present("debug") {
      println!("Printing debug info...");
    }

    if matches.is_present("symmetric") {
      println!("Run symmetric crypto ops");
    }

    if matches.is_present("asymmetric") {
      println!("Run asymmetric crypto ops")
    }
  }
}

fn run_keygen_cmd(args: clap::ArgMatches) {
  let f = args.subcommand_matches("keygen").unwrap();
  let size = f.value_of("size").unwrap();
  let dest = f.value_of("destination").unwrap();

  println!("==> generating rsa keypair of size {:?}", size);

  let keysize = keygen::KeySize::keysize_from_str(size);
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

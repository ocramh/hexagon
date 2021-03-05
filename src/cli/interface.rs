use clap::{load_yaml, App};

pub fn cli() {
  let yaml = load_yaml!("cli.yaml");
  let matches = App::from(yaml).get_matches();

  if let Some(ref _matches) = matches.subcommand_matches("keygen") {
    let f = matches.subcommand_matches("keygen").unwrap();
    let keysize = f.value_of("size").unwrap();
    let dest = f.value_of("destination").unwrap();
    println!(
      "generate rsa keypair of size {:?}, save at {:?}",
      keysize, dest
    );
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

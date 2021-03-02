use clap::{load_yaml, App};

pub fn cli() {
  let yaml = load_yaml!("cli.yaml");
  let matches = App::from(yaml).get_matches();

  if let Some(ref _matches) = matches.subcommand_matches("symmetric") {
    println!("do symmetric encryption")
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

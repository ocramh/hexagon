use clap::{load_yaml, App};

pub fn cli() {
  let yaml = load_yaml!("cli.yaml");
  let matches = App::from(yaml).get_matches();

  if let Some(ref matches) = matches.subcommand_matches("test") {
    if matches.is_present("debug") {
      println!("Printing debug info...");
    } else {
      println!("Printing debug info...");
    }
  }
}

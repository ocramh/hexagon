use crate::cli::tasks;
use clap::{App, AppSettings, Arg, SubCommand};

pub fn run() {
  let matches = App::new("hexagon")
    .name(
      r#"___
/  \ HEXAGON
\__/
    "#,
    )
    .version("1.0.0")
    .author("marco <ocramh11@gmail.com>")
    .about("A simple cryptography toolkit")
    .setting(AppSettings::SubcommandRequiredElseHelp)
    .subcommand(
      SubCommand::with_name("encrypt")
        .about("encrypt plaintext")
        .arg(
          Arg::with_name("input")
            .required(true)
            .long("input")
            .short("i")
            .takes_value(true)
            .help("input plaintext to encrypt"),
        )
        .arg(
          Arg::with_name("type")
            .required(true)
            .default_value("symmetric")
            .long("type")
            .short("t")
            .takes_value(true)
            .possible_values(&["symmetric", "asymmetric"])
            .help("type of encryption to perform"),
        )
        .arg(
          Arg::with_name("key")
            .required_if("type", "asymmetric")
            .long("key")
            .short("k")
            .takes_value(true)
            .help("path of the public key to use for encryption"),
        )
        .arg(
          Arg::with_name("secret")
            .required_if("type", "symmetric")
            .long("secret")
            .short("s")
            .takes_value(true)
            .help("secret to use for encryption"),
        ),
    )
    .subcommand(
      SubCommand::with_name("decrypt")
        .about("decrypt ciphertext")
        .arg(
          Arg::with_name("input")
            .required(true)
            .long("input")
            .short("i")
            .takes_value(true)
            .help("input to the base64 encoded ciphertext to decrypt"),
        )
        .arg(
          Arg::with_name("type")
            .required(true)
            .default_value("symmetric")
            .long("type")
            .short("t")
            .takes_value(true)
            .possible_values(&["symmetric", "asymmetric"])
            .help("type of decryption to perform"),
        )
        .arg(
          Arg::with_name("key")
            .required_if("type", "asymmetric")
            .long("key")
            .short("k")
            .takes_value(true)
            .help("path of the private key to use for decryption"),
        )
        .arg(
          Arg::with_name("secret")
            .required_if("type", "symmetric")
            .long("secret")
            .short("s")
            .takes_value(true)
            .help("secret to use for decryption"),
        )
        .arg(
          Arg::with_name("nonce")
            .required_if("type", "symmetric")
            .long("nonce")
            .short("n")
            .takes_value(true)
            .help("nonce or init vector to use for for decryption"),
        ),
    )
    .subcommand(
      SubCommand::with_name("keygen")
        .about("generates public/private key pair")
        .arg(
          Arg::with_name("size")
            .required(true)
            .long("size")
            .short("s")
            .takes_value(true)
            .possible_values(&["1024", "2048", "4096"])
            .default_value("2048")
            .help("key size in bytes"),
        )
        .arg(
          Arg::with_name("destination")
            .required(true)
            .long("dest")
            .short("d")
            .takes_value(true)
            .default_value("./")
            .help("destination path where the key pair will be saved"),
        ),
    )
    .get_matches();

  if let Some(arg_matches) = matches.subcommand_matches("encrypt") {
    return tasks::run_encrypt_cmd(arg_matches);
  }

  if let Some(arg_matches) = matches.subcommand_matches("decrypt") {
    return tasks::run_decrypt_cmd(arg_matches);
  }

  if let Some(arg_matches) = matches.subcommand_matches("keygen") {
    return tasks::run_keygen_cmd(arg_matches);
  }

  eprintln!("unknown command");
  std::process::exit(1);
}

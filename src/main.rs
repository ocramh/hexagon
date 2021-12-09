extern crate rand;

use anyhow::Result;
mod cli;
mod crypto;
use crate::cli::cli as hexagon_cli;

fn main() -> Result<()> {
  hexagon_cli::run();
  Ok(())
}

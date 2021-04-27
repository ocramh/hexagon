extern crate rand;

use anyhow::Result;
mod cli;
mod crypto;
use crate::cli::tasks;

fn main() -> Result<()> {
  tasks::run();
  Ok(())
}

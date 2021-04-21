extern crate rand;

use anyhow::Result;
mod cli;
mod crypto;
mod filesys;
use crate::cli::tasks;

fn main() -> Result<()> {
  tasks::run();
  Ok(())
}

use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum FsError {
  #[error("invalid path: {0}")]
  _InvalidPath(String),
}

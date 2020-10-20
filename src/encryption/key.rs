use std::fmt;

#[derive(Clone)]
pub struct Key(pub [u8; 32]);

impl fmt::Display for Key {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "[{}_ _ _ _ _{}]", self.0[1], self.0[self.0.len() - 1])
  }
}

extern crate openssl;

use std::error::Error;
use openssl::rsa::{Rsa};

const KEY_SIZE: u32 = 4096;
 
pub type BoxResult<T> = Result<T, Box<dyn Error>>;

pub struct KeyManager {
    pub publkey_path: String,
    pub privkey_path: String,
}

impl KeyManager {
    pub fn new_keypair(&self) -> BoxResult<()> {
        let rsa = Rsa::generate(KEY_SIZE).unwrap();

        let priv_key: Vec<u8> = rsa.private_key_to_pem().unwrap(); 
        let publ_key: Vec<u8> = rsa.public_key_to_pem().unwrap(); 
    
        println!("private k: {}", String::from_utf8(priv_key).unwrap());
        println!("public k: {}", String::from_utf8(publ_key).unwrap());
    
        Ok(())
    }
}
use std::{borrow::Cow, fs::File, io::{self, Read}};
use base64::prelude::*;

mod set1;
mod set2;

fn main() -> Result<(), io::Error> {
    
    let mut file = File::open("data/s2/10.txt")?;
    let mut b64 = String::from("");
    let _ = file.read_to_string(&mut b64);
    let b64 = b64.trim();
    let encrypted = BASE64_STANDARD.decode(b64).unwrap();
    let key = "YELLOW SUBMARINE".as_bytes();

    let decrypted = set2::decrypt_aes_cbc(&encrypted, &key, None, 16);
   
    let encrypted = set2::encrypt_aes_cbc(&decrypted, &key, None);

    //let decrypted = set2::decrypt_aes_cbc(&encrypted, &key, None, 32);

    match String::from_utf8_lossy(&decrypted) {
        Cow::Borrowed(s) => println!("{}", s), // Valid UTF-8
        Cow::Owned(s) => println!("{}", s),    // Invalid UTF-8, lossy conversion
    }

    Ok(())
}

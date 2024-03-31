use core::panic;

use openssl::symm::{encrypt, Cipher};

use crate::set1::{decrypt_aes_ecb, fixed_xor};

pub fn pkcs7_padding(data: &[u8], block_size: usize) -> Vec<u8> {
    if data.len() == block_size {
        return data.to_vec();
    }
    let mut data = data.to_vec();
    let padding_len = data.len() % block_size;
    data.resize(data.len() + padding_len, padding_len as u8);
    data
}

pub fn is_pkcs7_padded(data: &[u8]) -> bool {
    if let Some(&last_byte) = data.last() {
        let pad_len = last_byte as usize;
        if let Some(s) = data.get(data.len() - pad_len as usize..) {
            return s.iter().all(|&x| x as usize == pad_len); 
        }
    }
    false
}

pub fn pkcs7_unpadding(data: &[u8]) -> Vec<u8> {
    if is_pkcs7_padded(data) {
        if let Some(&d) = data.last() {
            return data[..data.len()- d as usize].to_vec();
        }
    }
    data.to_vec()
}


pub fn encrypt_aes_ecb(plaintext: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8> {
    let block_size = 16;
    let cipher = Cipher::aes_128_ecb();
    let ciphertext = encrypt(cipher, &key, iv, &pkcs7_padding(&plaintext, block_size)).expect("Error encrypting AES");
    ciphertext[..16].to_vec()
}

pub fn encrypt_aes_cbc(plaintext: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8> {
    let block_size = 16; // AES block size is 16 bytes
    let mut cipher_text = Vec::new();
    let mut initial_vector = match iv {
        Some(v) => {
            if v.len() != block_size {
                panic!("Initial vector must be {} bytes long!", block_size);
            }
            v.to_vec()
        },
        None => vec![0u8; block_size],
    };

    for chunk in plaintext.chunks(block_size) {
        let plaintext_xor = fixed_xor(&chunk, &initial_vector);
        let encrypted_chunk = encrypt_aes_ecb(&plaintext_xor, &key, None);
        cipher_text.extend_from_slice(&encrypted_chunk);
        initial_vector = encrypted_chunk.clone();
    }
    cipher_text
}

pub fn decrypt_aes_cbc(ciphertext: &[u8], key: &[u8], iv: Option<&[u8]>) -> Vec<u8> {
    let block_size = 16;
    let mut iv = match iv {
        Some(iv) => {
            if iv.len() != block_size {
                panic!("Initial vector must be {} bytes long!", block_size);
            }
            iv.to_vec()
        },
        None => vec![0u8; block_size],
    };
    
    let mut plain_text = Vec::new();

    for chunk in ciphertext.chunks(block_size) {
        let decrypted_chunk = decrypt_aes_ecb(chunk, &key, false);
        let plaintext_xor = fixed_xor(&decrypted_chunk, &iv);
        plain_text.extend_from_slice(&plaintext_xor);
        iv = chunk.to_vec(); // Update IV for the next iteration
    }
    pkcs7_unpadding(&plain_text)
}


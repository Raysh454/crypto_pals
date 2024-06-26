use core::f32;
use std::collections::HashMap;
use base64::prelude::*;
use openssl::symm::{decrypt, Cipher, Crypter, Mode};

pub fn repeating_key_xor(hex_arr: &[u8], key_hex: &[u8]) -> Vec<u8> {
    (0..hex_arr.len())
        .map(|i| hex_arr[i] ^ key_hex[i % key_hex.len()])
        .collect()
}

pub fn decode_repeating_key_xor(parsed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut sum = 0.0;
    let mut num_of_blocks = 0.0;
    let mut normalized_edit_distance = f32::MAX;
    let mut keylen = 0;
    
    //Find keysize
    for keysize in 2..=40 {
        for i in (keysize..parsed.len()).step_by(keysize) {
            if let (Some(block1), Some(block2)) = (parsed.get(i - keysize..i), parsed.get(i..i + keysize)) {
                sum += hamming_distance(block1, block2).expect("Hamming Dist error") as f32 / keysize as f32;
                num_of_blocks += 1.0;
            }
        }
        let normalized_dist = sum / num_of_blocks;
        if normalized_dist < normalized_edit_distance {
            normalized_edit_distance = normalized_dist;
            keylen = keysize;
        }
        sum = 0.0;
        num_of_blocks = 0.0;
    }

    //Convert parsed to blocks of keysize
    let chunks: Vec<_> = parsed.chunks(keylen).collect();

    //Transpose chunks
    let  transpose: Vec<Vec<_>> = (0..keylen)
        .map(|i| chunks.iter().filter_map(|chunk| chunk.get(i)).copied().collect())
        .collect();

    //Find key by decoding single byte
    let key: Vec<_> = transpose
        .iter()
        .map(|block| {
            let (key_byte, _) = decode_single_byte_xor_cipher(block);
            key_byte
        })
        .collect();

    //Decode using key
    let decoded = repeating_key_xor(&parsed, &key);
    (decoded, key)
}


pub fn decode_single_byte_xor_cipher(decoded_buf: &[u8]) -> (u8, String) {
    let mut result: String = Default::default();
    let mut temp: String = Default::default();
    let mut key = 0;
    let mut score = 0;
    for i in 20..=125 {
        let mut cur_score = 0;
        for c in decoded_buf {
            let xor = c ^ i;
            temp += &format!("{}", xor as char);
            if (xor > 64 && xor < 90) || (xor > 96 && xor < 123) || ". ,;:'\"".contains(xor as char) {
                cur_score += 1;
            }
        }
        if cur_score > score {
            score = cur_score;
            key = i;
            result = temp.clone();
        }
        temp.clear();
    }
    (key, result)
}

pub fn hex_to_b64(hex_string:& str) -> String {
    let bytes = parse_hex(hex_string, true); 
    BASE64_STANDARD.encode(&bytes)
}

pub fn fixed_xor(buffer1: &[u8], buffer2: &[u8]) -> Vec<u8> {
    buffer1.iter().zip(buffer2.iter()).map(|(&x, &y)| x ^ y).collect()
}

pub fn parse_hex(buf: &str, even: bool) -> Vec<u8> {
    (0..buf.len())
        .step_by(if even { 2 } else { 1 })
        .map(|i| u8::from_str_radix(&buf[i..i + if even { 2 } else { 1 }], 16).unwrap())
        .collect()
}

pub fn encode_hex(buf: &str) -> String {
    buf.as_bytes()
        .iter()
        .map(|c| format!("{:0>2x}", c))
        .collect()
}

pub fn hamming_distance(buf1: &[u8], buf2: &[u8]) -> Result<u32, &'static str> {
    if buf1.len() != buf2.len() {
        return Err("Strings must have equal length");
    }

    let distance = buf1.iter()
        .zip(buf2.iter())
        .map(|(c1, c2)| (c1 ^ c2).count_ones())
        .sum();

    Ok(distance)
}

pub fn decrypt_aes_ecb(ciphertext: &[u8], key: &[u8], pad: bool) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, None).expect("Error creating decrypter");
    decrypter.pad(pad);

    let mut output = vec![0; ciphertext.len() + cipher.block_size()];
    let decrypted_len = decrypter.update(ciphertext, &mut output).expect("Error extracting decrypted_len");
    let final_len = decrypter.finalize(&mut output[decrypted_len..]).expect("Error extracting final_len");

    // Resize the output to the final decrypted length
    output.resize(decrypted_len + final_len, 0);

    // Extract the decrypted data
    output[..decrypted_len + final_len].to_vec()
}

pub fn detect_aes_ecb(chipher_text: &[u8]) -> bool {
    let blocks: Vec<_> = chipher_text.chunks(16).collect(); 
    let mut block_count = HashMap::new();
    let mut num_of_blocks_colliding = 0;

    for block in blocks {
        match block_count.get(&block) {
            Some(c) => {
                num_of_blocks_colliding += 1;
                block_count.insert(block, c + 1)
            },
            None => block_count.insert(block, 1)
        };
    }
    num_of_blocks_colliding > 1
}

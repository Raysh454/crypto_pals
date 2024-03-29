use std::{error::Error, fs::File, io::{BufRead, BufReader}};
mod set1;

fn main() -> Result<(), Box<dyn Error>> {
    let file = File::open("8.txt")?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        match line {
            Ok(content) => {
                let trimmed = content.trim();
                let parsed = set1::parse_hex(&trimmed, true);
                if set1::detect_aes_ecb(&parsed) {
                    println!("{} is ecb encrypted.", content);
                }
            }
            Err(err) => {
                println!("Error reading line: {}", err);
                continue;
            }
        }
    }
    

    Ok(())
}

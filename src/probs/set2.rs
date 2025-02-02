use crate::crypt::cipher;
use crate::util;
use crate::probs;

pub fn prob9() {
    let data = b"YELLOW SUBMARINE";
    let pkcs7 = cipher::padding::pkcs7(data, 20);
    println!("Problem 9: Padded result of '{}' by PKCS#7 of length 20", String::from_utf8(data.to_vec()).unwrap());
    println!("\t{}", util::hex(&pkcs7));
    assert_eq!(pkcs7, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}

pub fn prob10() {
    let data = util::read_b64_as_bytes("resources/10.txt");
    let iv = vec![0, 16];
    let key = b"YELLOW SUBMARINE";
    let dec = cipher::aes_cbc_128_dec(&data, key, &iv).unwrap();
    println!("Problem 10: Decryption by AES-CBC with wrong key");
    for block in dec.chunks(16) {
        println!("\t{}", util::as_latin(block));
    }
}

pub fn prob11() {
    use rand::Rng;

    let data = util::read_as_u8("resources/11.txt").unwrap();
    let mut remain: i32 = data.len() as i32;
    let mut offset = 0usize;
    let mut rng = rand::thread_rng();
    println!("Problem 11: ECB or CBC");
    let mut count = 0;
    while remain > 0 {
        let sz = std::cmp::min(rng.gen_range(1..2) * 16, remain) as usize;
        print!("Block {}: ", count);
        if let Ok(ebc_or_cbc) = probs::aes_encryption_oracle(&data[offset..offset+sz]) {
            println!("\t{}", ascii_dump(&ebc_or_cbc));
        }
        else {
            println!("\tEncryption error!")
        }
        remain -= sz as i32;
        offset += sz as usize;
        count += 1;
    }
}

pub fn prob12() {
    println!("Problem12: Crack AES-ECB using encryption oracle");
    
    for i in 1..17 {
        let prefix = "A".repeat(i);
        let pb = prefix.as_bytes();
        let result = super::aes_128_ecb_oracle(pb).unwrap();

        let blocks: Vec<Vec<u8>> = result.chunks(16).collect();
        let blocks_uniq = blocks
        println!("Number of blocks: {}, {}", blocks.len(), prefix);
    }
    // Decrypt ciphertext under AES-ECB
}
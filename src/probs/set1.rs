use cryptopals::util::*;
use cryptopals::crypt::*;


pub fn prob1() {
    let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let bytes = fromhex(hex_str).expect("Failed to convert hex string to byte array.");
    let b64 = b64(&bytes);

    println!("Problem 1: {}", b64_str == b64);
}

pub fn prob2() {
    let data_hex = "1c0111001f010100061a024b53535009181c";
    let key_hex  = "686974207468652062756c6c277320657965";
    let answer   = "746865206b696420646f6e277420706c6179";

    let mut data = fromhex(data_hex).unwrap();
    let key = fromhex(key_hex).unwrap();
    ixor(&mut data, &key);

    println!("Problem 2: {}", data == fromhex(answer).unwrap());
}

pub fn prob3() {
    let ctxt_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let ctxt = fromhex(ctxt_hex).unwrap();
    let cand = find_single_xor_key(&ctxt, is_en, 5);
    println!("Problem 3: Candidates are");
    for key in cand {
        let dec = xor(&ctxt, &vec![key]);
        let cnt = count(&dec, is_en);
        let plain = String::from_utf8(dec).unwrap();
        println!("\tKey={}, Score={}, Decryption=\"{}\"", key, cnt, plain);
    }
}

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::iter::Iterator;

pub fn prob4() {
    let fname = "resources/4.txt";
    let file = File::open(fname).expect("File not found.");
    let reader = BufReader::new(file);
    let mut scores: Vec<(Vec<u8>, u8, i32)> = Vec::new();
    for line in reader.lines() {
        if let Ok(v) = line {
            if let Ok(bytes) = fromhex(&v) {
                let key = find_single_xor_key(&bytes, is_en, 1)[0];
                let ctxt = xor(&bytes, &vec![key]);
                let score = count(&ctxt, is_en) as i32;
                scores.push((ctxt, key, score));
            }
        }        
    }
    scores.sort_by(|a, b| b.2.cmp(&a.2));
    println!("Problem 4: Candidates are");
    for t in &scores[0..5] {
        if let Ok(plain) = std::str::from_utf8(&t.0) {
            println!("\tkey={}, score={}, decryption=\"{}\"", t.1, t.2, &plain);
        }
    }
}

pub fn prob5() {
    let ptxt = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".as_bytes();
    let key = "ICE".as_bytes();
    let answer = fromhex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();
    let ctxt = xor(&ptxt, &key);
    println!("Problem 5: {}", answer == ctxt);
}

pub fn prob6() {
    let fname = "resources/6.txt";
    let file = File::open(fname).expect("File not found.");
    let reader = BufReader::new(file);
    let mut b64 = String::new();
    for line in reader.lines() {
        b64 += &line.unwrap();
    }
    let data = fromb64(&b64).unwrap();
    let mut scores: Vec<(usize, f64)> = Vec::new();

    // println!("{}", hex(&data));

    // calculate normalized score, less better
    for len in 2..40 {
        let mut prev: &[u8] = &data[0..len];
        let mut score: f64 = 0.;
        let blk_cnt = 3;
        for j in 1..blk_cnt {
            let curr = &data[j*len..j*len+len];
            score += hamming_distance(prev, curr) as f64 / len as f64;
            prev = curr;
        }
        score /= (blk_cnt - 1) as f64;
        scores.push((len, score));        
    }
    scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    println!("Problem 6");
    let mut best_count = 0;
    for pair in &scores[0..10] {
        let len = pair.0;
        println!("\tLength: {}, Score: {}", len, pair.1);

        // Transpose the data by the length
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for i in 0..len {
            let seg: Vec<u8> = data.iter().skip(i).step_by(len).copied().collect();   
            let found = find_single_xor_key(&seg, is_en, 1);
            let mut key: Vec<u8> = Vec::new();
            for k in found {
                let dec = xor(&data[0..40], &vec![k]);
                if let Ok(_) = std::str::from_utf8(&dec) {
                    key.push(k);
                }
            }
            keys.push(key);
        }

        let key_product: Vec<Vec<u8>> = cartesian_product(&keys);
        for klist in key_product {
            let dec = xor(&data, &klist);
            let cnt = count(&dec, is_en);
            if cnt > best_count {
                print!("\t\tKey: {}({}), ", ascii_dump(&klist), hex(&klist));
                for b in &dec[0..80] {
                    match b {
                        0x20..=0x7e => print!("{}", *b as char),
                        _ => print!(".")
                    }
                }   
                println!();
                best_count = cnt;
            }
        }
    }

    let dec = xor(&data, b"TERMINATOR\x00\0X\0\0BRING\0THE\0NOISE");
    for b in &dec[0..80] {
        match b {
            0x20..=0x7e => print!("{}", *b as char),
            _ => print!(".")
        }
    }
    println!();
}

pub fn prob7() {
    use openssl::cipher::Cipher;
    use openssl::cipher_ctx::CipherCtx;

    let fname = "resources/7.txt";
    let data = read_b64_as_bytes(fname);
    let key = b"YELLOW SUBMARINE";

    assert_eq!(0, data.len() % 16);
    assert_eq!(16, key.len());

    let aes = Cipher::aes_128_ecb();
    let mut ctx = CipherCtx::new().unwrap();
    ctx.decrypt_init(Some(aes), Some(key), None).unwrap();
    let mut ptxt = vec![];
    ctx.cipher_update_vec(&data, &mut ptxt).unwrap();
    println!("Problem 7:");
    println!("{}", ascii_dump(&ptxt));
}

pub fn prob8() {
    use std::collections::HashSet;

    let fname = "resources/8.txt";
    println!("Problem 8: Ciphertext by AES-ECB");

    if let Ok(file) = File::open(fname) {
        let reader = BufReader::new(file);

        for line_res in reader.lines() {
            if let Ok(hex_str) = line_res {
                if let Ok(data) = fromhex(&hex_str) {
                    let blocks: Vec<String> = data.chunks(16).map(|d| hex(d)).collect();
                    let block_set: HashSet<String> = HashSet::from_iter(blocks.clone());
                    if blocks.len() != block_set.len() {
                        for b in blocks {
                            println!("\t{}", b);
                        }
                    }
                }
            }
        }
    }
    
}

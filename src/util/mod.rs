pub fn cartesian_product<T>(lists: &Vec<Vec<T>>) -> Vec<Vec<T>>
where
    T: Copy,
{
    let mut res = vec![];

    let mut list_iter = lists.iter();
    if let Some(first_list) = list_iter.next() {
        for &i in first_list {
            res.push(vec![i]);
        }
    }
    for l in list_iter {
        let mut tmp = vec![];
        for r in res {
            for &el in l {
                let mut tmp_el = r.clone();
                tmp_el.push(el);
                tmp.push(tmp_el);
            }
        }
        res = tmp;
    }
    res
}

pub fn is_en(c: u8) -> bool {
    match c {
        b'A'..=b'Z' => true,
        b'a'..=b'z' => true,
        _ => false,
    }
}

pub fn not_en(c: u8) -> bool {
    !is_en(c)
}

pub fn is_ascii(c: u8) -> bool {
    return c == 0x09 || c == 0x0a || c == 0x0d || (0x20 <= c && c <= 0x7e);
}

pub fn not_ascii(c: u8) -> bool {
    !is_ascii(c)
}

pub fn is_ascii_zero(c: u8) -> bool {
    return is_ascii(c) || c == 0;
}

pub fn not_ascii_zero(c: u8) -> bool {
    !is_ascii_zero(c)
}

pub fn count(data: &[u8], pred: fn(u8) -> bool) -> usize {
    return data.iter().filter(|&c| pred(*c)).count();
}

pub fn ascii_dump(data: &[u8]) -> String {
    let mut ret = String::new();
    for b in data {
        match b {
            0x20..=0x7e => ret.push(*b as char),
            _ => ret.push('.'),
        }
    }
    ret
}

pub fn b64(bytes: &[u8]) -> String {
    static B64STR: [char; 64] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
        'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
        'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
        'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    ];
    let mut b64 = String::new();
    let mut i = 0;
    let end = bytes.len() * 8;
    let mut v = 0;
    let mut r = 6;
    while i < end {
        let l = i % 8;
        let m = std::cmp::min(r, 8 - l);
        let n = 8 - l - m;

        v <<= r;
        v |= (bytes[i / 8] & (((1 as u16) << (m + n)) - 1) as u8) >> n;

        r -= m;
        if r == 0 {
            r = 6;
            b64.push(B64STR[v as usize]);
            v = 0;
        }

        i += m;
    }

    if v != 0 {
        v <<= r;
        b64.push(B64STR[v as usize]);
        if end % 24 == 8 {
            b64 += "==";
        } else {
            b64 += "=";
        }
    }
    b64
}

pub fn fromb64(b64: &str) -> Result<Vec<u8>, String> {
    let mut ret: Vec<u8> = Vec::new();
    let mut buf: [u8; 4] = [0, 0, 0, 0];
    let mut i = 0;
    let bytes = b64.as_bytes();
    let mut processed_pad = false;
    while i < bytes.len() {
        if processed_pad {
            return Err(String::from("Invalid padding"));
        }
        let w = &bytes[i..i + 4];
        for (j, c) in w.iter().enumerate() {
            let v: u8;
            match *c as char {
                'A'..='Z' => v = *c - ('A' as u8),
                'a'..='z' => v = *c - ('a' as u8) + 26,
                '0'..='9' => v = *c - ('0' as u8) + 52,
                '+' => v = 62,
                '/' => v = 64,
                '=' => v = 0,
                _ => return Err(format!("Invalid base64 char: {}", c)),
            }
            buf[j] = v;
        }
        i += 4;

        /*
            w  xxoooooo xxoooo oo xxoooooo xxoooooo
            b1   ======   ==
            b2              ====   ====
            b3                         ==    ======
        */
        let b1 = (buf[0] << 2) | (buf[1] >> 4);
        let b2 = ((buf[1] & 0xf) << 4) | (buf[2] >> 2);
        let b3 = ((buf[2] & 0x3) << 6) | buf[3];

        if w[2..] == [b'=', b'='] && w[0] != b'=' && w[1] != b'=' {
            ret.push(b1);
            processed_pad = true;
        } else if w[3] == b'=' && w[0] != b'=' && w[1] != b'=' && w[2] != b'=' {
            ret.push(b1);
            ret.push(b2);
            processed_pad = true;
        } else if w[0] != b'=' && w[1] != b'=' && w[1] != b'=' && w[2] != b'=' {
            ret.push(b1);
            ret.push(b2);
            ret.push(b3);
        } else {
            return Err(String::from("Invalid padding"));
        }
    }
    Ok(ret)
}

pub fn fromhex(hex_str: &str) -> Result<Vec<u8>, String> {
    // Check length
    if hex_str.len() & 1 == 1 {
        return Err("Invalid hex length.".to_string());
    }

    // Check charset
    let mut bytes: Vec<u8> = vec![0; hex_str.len() / 2];
    for (i, c) in hex_str.chars().enumerate() {
        let mut v: u32 = c as u32;
        // Range match
        match c {
            '0'..='9' => v -= 0x30,
            'A'..='F' => v -= 0x41 - 10,
            'a'..='f' => v -= 0x61 - 10,
            _ => return Err(format!("Invalid hex char: {c}")),
        }
        bytes[i / 2] |= (v as u8) << (if i % 2 == 0 { 4 } else { 0 });
    }
    Ok(bytes)
}

pub fn ixor(data: &mut [u8], key: &[u8]) {
    for i in 0..data.len() {
        data[i] ^= key[i % key.len()];
    }
}

pub fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ret: Vec<u8> = Vec::with_capacity(data.len());
    for i in 0..data.len() {
        ret.push(data[i] ^ key[i % key.len()]);
    }
    ret
}

pub fn _hex(b: u8) -> Result<char, String> {
    match b {
        0..=9 => Ok((0x30 + b) as char),
        10..=15 => Ok((0x41 + b - 10) as char),
        _ => Err(format!("Invalid integer for radix 16: {}", b)),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes.iter() {
        hex.push(_hex(b >> 4).unwrap());
        hex.push(_hex(b & 0xf).unwrap());
    }
    hex
}

pub fn count_ones(b: u8) -> usize {
    static NIBBLE_LOOKUP: [u8; 16] = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];
    let z: usize = b as usize;
    (NIBBLE_LOOKUP[z & 0x0F] + NIBBLE_LOOKUP[z >> 4]) as usize
}

pub fn hamming_distance(b1: &[u8], b2: &[u8]) -> usize {
    let mut d: usize = 0;
    let shorter = if b1.len() < b2.len() { b1 } else { b2 };
    let longer = if b1.len() > b2.len() { b1 } else { b2 };
    let mut i = 0;
    while i < shorter.len() {
        d += count_ones(b1[i] ^ b2[i]);
        i += 1;
    }
    while i < longer.len() {
        d += count_ones(longer[i]);
        i += 1;
    }
    d
}

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::io::prelude::*;
use std::iter::Iterator;

pub fn read_b64_as_bytes(fname: &str) -> Vec<u8> {
    let file = File::open(fname).expect("File not found.");
    let reader = BufReader::new(file);
    let mut b64 = String::new();
    for line in reader.lines() {
        b64 += &line.unwrap();
    }
    fromb64(&b64).unwrap()
}

pub fn read_as_u8(fname: &str) -> std::io::Result<Vec<u8>> {
    let f = File::open(fname)?;
    let mut ret = Vec::new();
    let mut reader = BufReader::new(f);
    reader.read_to_end(&mut ret)?;
    Ok(ret)
}

pub fn as_latin(data: &[u8]) -> String {
    let mut ret = String::with_capacity(data.len());
    for b in data {
        match b {
            0x20..=0x7e => ret.push(*b as char),
            _ => ret.push('.')
        }
    }
    ret
}
fn main() {
    let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let b64str: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".chars().collect();

    // Check length
    if hex_str.len() & 1 == 1 {
        eprintln!("Invalid hex length.");        
    }

    // Check charset
    let mut bytes: Vec<u8> = vec![0; hex_str.len() / 2];
    for (i, c) in hex_str.chars().enumerate() {
        let mut v: u8 = c as u8;
        // 0-9
        if 0x30 <= v && v <= 0x39 {
            v -= 0x30;
        }
        // A-F
        else if 0x41 <= v && v <= 0x46 {
            v -= 0x41;
            v += 10;
        }
        // a-f
        else if 0x61 <= v && v <= 0x66 {
            v -= 0x61;
            v += 10;
        }
        else {
            eprintln!("Invalid hex char: {}({})", c, v);
            return;
        }

        if i % 2 == 0 {
            v <<= 4;            
        }
        bytes[i/2] |= v;
    }

    let mut b64 = String::new();
    let mut i = 0;
    let end = bytes.len() * 8;
    let mut v = 0;
    let mut r = 6;
    while i < end {
        let l = i % 8;
        let m = std::cmp::min(r, 8-l);
        let n = 8 - l - m;

        v <<= r;
        v |= (bytes[i/8] & (((1 as u16) << (m+n))-1) as u8) >> n;
        
        r -= m;
        if r == 0 {
            r = 6;
            b64.push(b64str[v as usize]);
            v = 0;
        }

        i += m;
    }

    println!("{}", b64_str == b64);
}
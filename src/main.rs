fn fromhex(hex_str: &str) -> Result<Vec<u8>, String> {
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
        bytes[i/2] |= (v as u8) << (if i % 2 == 0 { 4 } else { 0 });
    }
    Ok(bytes)
}

fn tob64(bytes: &Vec<u8>) -> String {
    static B64STR: [char; 64] = [
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
        '0','1','2','3','4','5','6','7','8','9','+','/'
    ];
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
            b64.push(B64STR[v as usize]);
            v = 0;
        }

        i += m;
    }
    b64
}

fn main() {
    let hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    let bytes = fromhex(hex_str).expect("Failed to convert hex string to byte array.");
    let b64 = tob64(&bytes);

    println!("Problem 1: {}", b64_str == b64);
}
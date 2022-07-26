
use crate::util;
use crate::crypt::{CryptError, cipher};

pub fn find_xor_key(ctxt: &[u8], max_len: usize) -> Vec<(f64, usize)> {
    let mut scores: Vec<(f64, usize)> = Vec::new();
    for len in 2..max_len {
        let f = &ctxt[0..len];
        let r = &ctxt[len + 1..2 * len];
        let d = util::hamming_distance(f, r) as f64;
        let score = d / len as f64;
        scores.push((score, len));
    }

    scores.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    scores
}

// Returns (key, en count) if such exists
pub fn find_single_xor_key(ctxt: &Vec<u8>, inc: fn(u8) -> bool, top_count: usize) -> Vec<u8> {
    let mut counts: Vec<(u8, usize)> = Vec::new();
    for k in 0..255 {
        let ptxt = util::xor(ctxt, &vec![k]);
        counts.push((k, util::count(&ptxt, inc)));
    }

    counts.sort_by(|a, b| b.1.cmp(&a.1));
    return counts[0..std::cmp::min(top_count, counts.len())]
        .iter()
        .map(|c| c.0)
        .collect();
}

// Weak source
pub fn rand_bytes(sz: usize) -> Result<Vec<u8>, CryptError> {
    use openssl::rand;
    let mut ret: Vec<u8> = Vec::with_capacity(sz);
    if let Err(_) = rand::rand_bytes(&mut ret) {
        Err(CryptError::RandomGenerationError)
    } else {
        Ok(ret)
    }
}

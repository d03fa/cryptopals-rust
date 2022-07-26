pub mod set1;
pub mod set2;

use crate::crypt::{CryptError, cipher};
use crate::util;


// Assume ptxt is multiple of 16
pub fn aes_encryption_oracle(ptxt: &[u8]) -> Result<Vec<u8>, CryptError> {
    if ptxt.len() % 16 != 0 {
        Err(CryptError::InvalidInputLength)
    }
    else {
        use rand::Rng;        
        let mut rng = rand::thread_rng();
        let prefix_len: usize = rng.gen_range(5..11);
        let suffix_len = 16 - prefix_len;
        let new_len = ptxt.len() + 16;
        let mut ptxt_new: Vec<u8> = vec![0; new_len];
        ptxt_new[..prefix_len].fill_with(|| prefix_len as u8);
        ptxt_new[new_len-suffix_len..].fill_with(|| suffix_len as u8);
        ptxt_new[prefix_len..new_len-suffix_len].copy_from_slice(ptxt);

        let key = rand_bytes(16)?;
        // ECB
        let mode: u8 = rng.gen_range(0..2);
        if mode == 0 {
            cipher::aes_ecb_128_enc(&ptxt_new, &key)
        }
        // CBC
        else {
            let iv = cipher::rand_bytes(16)?;
            cipher::aes_cbc_128_enc(&ptxt_new, &key, &iv)
        }
    }
}

pub fn aes_128_ecb_encryption_oracle(ptxt: &[u8]) -> Result<Vec<u8>, CryptError> {
    static SECRET_KEY:    &[u8] = b"Um9sbGluJyBpbiBt";
    static SECRET_MESSAGE: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A";
    let mut p: Vec<u8> = Vec::new();
    p.extend_from_slice(ptxt);
    p.extend_from_slice(&util::fromb64(SECRET_MESSAGE).unwrap());
    cipher::aes_ecb_128_enc(&cipher::padding::pkcs7(&p, 16), SECRET_KEY)
}
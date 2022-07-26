pub mod padding;

use std::str::FromStr;

use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

use crate::util::*;
use crate::crypt::CryptError;

// Assumes the plaintext is of length of multiple of 16
pub fn aes_128_block_enc(ptxt: &[u8], key: &[u8]) -> Vec<u8> {
    let aes = Cipher::aes_128_ecb();
    let mut ctx = CipherCtx::new().unwrap();
    let mut buf: Vec<u8> = vec![0; 32];
    ctx.encrypt_init(Some(aes), Some(key), None).unwrap();
    ctx.cipher_update(&ptxt, Some(&mut buf)).unwrap();
    buf.resize(16, 0);
    buf
}

pub fn aes_128_block_dec(ctxt: &[u8], key: &[u8]) -> Vec<u8> {
    let aes = Cipher::aes_128_ecb();
    let mut ctx = CipherCtx::new().unwrap();
    let mut buf: Vec<u8> = vec![0; 32];
    ctx.decrypt_init(Some(aes), Some(key), None).unwrap();
    ctx.cipher_update(&ctxt, Some(&mut buf)).unwrap();
    buf.resize(16, 0);
    buf
}

// ptxt should be length of muliple of 16
pub fn aes_cbc_128_enc(ptxt: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptError> {
    if ptxt.len() % 16 != 0 {
        Err(CryptError::InvalidInputLength)
    }
    else {
        let mut ctxt: Vec<u8> = vec![0; ptxt.len()];
        let mut prev = iv;
        let mut offset: usize = 0;
        for block in ptxt.chunks(16) {
            let bin = xor(block, prev);
            let eb = aes_128_block_enc(&bin, key);
            ctxt[offset..offset+16].copy_from_slice(&eb);
            prev = &ctxt[offset..offset+16];
            offset += 16;
        }
        Ok(ctxt)
    }
}

// ctxt should be length of multiple of 16
pub fn aes_cbc_128_dec(ctxt: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    if ctxt.len() % 16 != 0 {
        Err(String::from_str("Invalid ciphertext length").unwrap())
    }
        else {
        let mut ptxt: Vec<u8> = vec![0; ctxt.len()];
        let mut prev = iv;
        let mut offset: usize = 0;
        let blocks: Vec<&[u8]> = ctxt.chunks(16).collect();
        for i in 0..blocks.len() {
            let bin = blocks[i];
            let mut db = aes_128_block_dec(bin, key);
            ixor(&mut db, &prev);
            ptxt[offset..offset+16].copy_from_slice(&db);
            prev = &ctxt[offset..offset+16];
            offset += 16;
        }
        Ok(ptxt)
    }
}

pub fn aes_ecb_128_enc(ptxt: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptError> {
    if ptxt.len() % 16 != 0 {
        Err(CryptError::InvalidInputLength)
    }
    else {
        let mut ctxt = vec![0; ptxt.len()];
        let mut offset: usize = 0;
        for block in ptxt.chunks(16) {
            let eb = aes_128_block_enc(block, key);
            ctxt[offset..offset+16].copy_from_slice(&eb);                    
            offset += 16;
        }
        Ok(ctxt)
    }
}

pub fn aes_cbc_128_pkcs7_enc(ptxt: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptError> {
    let ptxt_padded = padding::pkcs7(ptxt, 16);
    aes_cbc_128_enc(&ptxt_padded, key, iv)
}

pub fn aes_cbc_128_pkcs7_dec(ctxt: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, CryptError> {
    let mut dec = aes_cbc_128_dec(ctxt, key, iv).unwrap();
    let pad_len = *dec.last().unwrap() as usize;
    if vec![pad_len as u8; pad_len] != dec[dec.len() - pad_len..] {
        Err(CryptError::InvalidPadding)
    }
    else {
        dec.resize(dec.len() - pad_len, 0);
        Ok(dec)
    }
}
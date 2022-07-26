pub mod cipher;
pub mod analysis;

#[derive(Debug)]
pub enum CryptError {
    InvalidInputLength,
    InvalidPadding,
    RandomGenerationError,
}

#[cfg(test)]
mod util_tests {
    use crate::util::*;

    #[test]
    pub fn test_b64() {
        assert_eq!(b64("".as_bytes()), "");
        assert_eq!(b64("f".as_bytes()), "Zg==");
        assert_eq!(b64("fo".as_bytes()), "Zm8=");
        assert_eq!(b64("foo".as_bytes()), "Zm9v");
        assert_eq!(b64("foob".as_bytes()), "Zm9vYg==");
        assert_eq!(b64("fooba".as_bytes()), "Zm9vYmE=");
        assert_eq!(b64("foobar".as_bytes()), "Zm9vYmFy");

        assert_eq!("".as_bytes(), fromb64("").unwrap());
        assert_eq!("f".as_bytes(), fromb64("Zg==").unwrap());
        assert_eq!("fo".as_bytes(), fromb64("Zm8=").unwrap());
        assert_eq!("foo".as_bytes(), fromb64("Zm9v").unwrap());
        assert_eq!("foob".as_bytes(), fromb64("Zm9vYg==").unwrap());
        assert_eq!("fooba".as_bytes(), fromb64("Zm9vYmE=").unwrap());
        assert_eq!("foobar".as_bytes(), fromb64("Zm9vYmFy").unwrap());
    }

    #[test]
    pub fn test_count_ones() {
        assert_eq!(count_ones(0x74 as u8), 4);
    }

    #[test]
    pub fn test_hamming_distance() {
        let s1 = b"this is a test";
        let s2 = b"wokka wokka!!!";
        assert_eq!(hamming_distance(s1, s2), 37);
    }
}

#[cfg(test)]
mod crypt_tests {
    use crate::util::fromhex;
    use crate::crypt::cipher;

    #[test]
    pub fn test_aes_128_block() {
        // Encryption
        let key = fromhex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let ptxt = fromhex("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let ctxt = cipher::aes_128_block_enc(&ptxt, &key);        
        assert_eq!(ctxt, fromhex("3ad77bb40d7a3660a89ecaf32466ef97").unwrap());

        // Decryption
        let ptxt = cipher::aes_128_block_dec(&ctxt, &key);        
        assert_eq!(ptxt, fromhex("6bc1bee22e409f96e93d7e117393172a").unwrap());
    }

    #[test]
    pub fn test_aes_128_cbc() {
        // Encryption
        let key = fromhex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = fromhex("000102030405060708090A0B0C0D0E0F").unwrap();
        let ptxt = fromhex("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let ctxt = cipher::aes_cbc_128_enc(&ptxt, &key, &iv).unwrap();
        assert_eq!(ctxt, fromhex("7649abac8119b246cee98e9b12e9197d").unwrap());

        let ptxt = cipher::aes_cbc_128_dec(&ctxt, &key, &iv).unwrap();
        assert_eq!(ptxt, fromhex("6bc1bee22e409f96e93d7e117393172a").unwrap());
    }

    #[test]
    pub fn test_pkcs7() {
        let data = b"YELLOW SUBMARINE";
        let padded_data = cipher::padding::pkcs7(data, 20);
        /*
        for b in &padded_data {
            print!("{:#02x} ", b);
        }
            */
        assert_eq!(padded_data, b"YELLOW SUBMARINE\x04\x04\x04\x04");
    }
}
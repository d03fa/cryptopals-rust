pub fn pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let len = data.len() + pad_len;
    let mut ret: Vec<u8> = vec![0; len];
    ret[..data.len()].copy_from_slice(data);            
    for i in 1..pad_len+1 {
        ret[len - i] = pad_len as u8;
    }
    ret
}

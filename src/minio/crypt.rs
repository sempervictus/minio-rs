use rand::Rng;
use std::error::Error;
use argon2::{Config, ThreadMode, Variant, Version};

use std::io::Write;
use sio::{Key, Nonce, Aad, EncWriter, DecWriter, Close};
use sio::ring::{AES_256_GCM, CHACHA20_POLY1305};

const ARGON2ID_AES_GCM: u8 = 0x00;
const ARGON2ID_CHACHA20_POLY1305: u8 = 0x01;
// const PBKDF2_AES_GCM: u8 = 0x02;

const ARGON_CONFIG: argon2::Config = Config {
    variant: Variant::Argon2id,
    version: Version::Version13,
    mem_cost: 64*1024,
    time_cost: 1,
    lanes: 4,
    thread_mode: ThreadMode::Parallel,
    secret: &[],
    ad: &[],
    hash_length: 32,
};

pub async fn sio_encrypt(
    password: String,
    data: Vec<u8>,
    gcm: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Random 32B of salt
    let salt = rand::thread_rng().gen::<[u8; 32]>();
    // Argon2id generated 32B array (from vector)
    let argon_vec = argon2::hash_raw(password.as_bytes(), &salt, &ARGON_CONFIG).unwrap();
    let mut argon_key = [0u8; 32];
    for (place, element) in argon_key.iter_mut().zip(argon_vec.iter()) {
        *place = *element;
    }
    // Random 8B of nonce prefix
    let nbytes = rand::thread_rng().gen::<[u8; 8]>();
    // Cipher-specific parameters
    let (mut ciphertext, cid) = if gcm {
        let nonce = Nonce::<AES_256_GCM>::new(nbytes);
        let key = Key::new(argon_key);
        let mut ciphertext: Vec<u8> = Vec::default();
        let mut writer = EncWriter::new(&mut ciphertext, &key, nonce, Aad::from(b""));
        writer.write_all(&data).unwrap();
        writer.close().unwrap();
        (ciphertext, ARGON2ID_AES_GCM)
    } else {
        let nonce = Nonce::<CHACHA20_POLY1305>::new(nbytes);
        let key = Key::new(argon_key);
        let mut ciphertext: Vec<u8> = Vec::default();
        let mut writer = EncWriter::new(&mut ciphertext, &key, nonce, Aad::from(b""));
        writer.write_all(&data).unwrap();
        writer.close().unwrap();
        (ciphertext, ARGON2ID_CHACHA20_POLY1305)
    };
    // Build final buffer
    let mut encbuf = salt.clone().to_vec();
    encbuf.push(cid);
    encbuf.append(&mut nbytes.to_vec());
    encbuf.append(&mut ciphertext);
    Ok(encbuf)
}

pub async fn sio_decrypt(password: String, data: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let salt = &data[0..32].to_vec();
    let cid = &data[32]; // unused for now, selector for ciphers
    let gcm: bool = cid == &ARGON2ID_AES_GCM;
    // Nonce 8B array from vec
    let nonce_vec = data[33..41].to_vec();
    let mut nbytes = [0u8; 8];
    for (place, element) in nbytes.iter_mut().zip(nonce_vec.iter()) {
        *place = *element;
    }
    let ctext = &data[41..].to_vec();
    // Argon2id generated 32B array (from vector)
    let argon_vec = argon2::hash_raw(password.as_bytes(), &salt, &ARGON_CONFIG).unwrap();
    let mut argon_key = [0u8; 32];
    for (place, element) in argon_key.iter_mut().zip(argon_vec.iter()) {
        *place = *element;
    }
    // Decryption with selected cipher
    let plaintext = if gcm {
        let nonce = Nonce::<AES_256_GCM>::new(nbytes);
        let key = Key::new(argon_key);
        let mut plaintext: Vec<u8> = Vec::default();
        let mut writer = DecWriter::new(&mut plaintext, &key, nonce, Aad::from(b""));
        writer.write_all(&ctext).unwrap();
        writer.close().unwrap();
        plaintext
    } else {
        let nonce = Nonce::<CHACHA20_POLY1305>::new(nbytes);
        let key = Key::new(argon_key);
        let mut plaintext: Vec<u8> = Vec::default();
        let mut writer = DecWriter::new(&mut plaintext, &key, nonce, Aad::from(b""));
        writer.write_all(&ctext).unwrap();
        writer.close().unwrap();
        plaintext
    };
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor;
    #[test]
    fn verify_gcm_crypt() {
        let password = "secret".to_owned();
        let plaintext = "this is a string".as_bytes().to_vec();
        let ciphertext =
            executor::block_on(sio_encrypt(password.clone(), plaintext.clone(), true)).unwrap();
        let decrypted = executor::block_on(sio_decrypt(password, ciphertext)).unwrap();
        assert_eq!(plaintext, decrypted);
    }
    #[test]
    fn verify_chacha_crypt() {
        let password = "secret".to_owned();
        let plaintext = "this is a string".as_bytes().to_vec();
        let ciphertext =
            executor::block_on(sio_encrypt(password.clone(), plaintext.clone(), false)).unwrap();
        let decrypted = executor::block_on(sio_decrypt(password, ciphertext)).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}

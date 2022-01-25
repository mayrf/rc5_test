//! # RC5
//!
//! A Rust implementation of the rc5 cipher for word sizes of 8, 16, 32 and 64 bits.
//!
//!

use std::vec;
use std::cmp;
use rayon::prelude::*; 

/// Holds the configuratrion parameters of RC5
///
/// **v:** version 
///
/// **w:** word sizes in bits 
///
/// **r:** number of rounds 
///
/// **b:** size of secred key in bytes
pub struct Config {   
    pub v: usize,               // version
    pub w: usize,               // word size
    pub r: usize,               // number of rounds
    pub b: usize,               // number of bytes of secred key 
}

impl Config {

/// Creates new instance of the Config struct with version set to 1.  
    pub fn new(w:usize, r:usize, b:usize) -> Config {
        Config {
            v:  1,
            w,
            r,
            b,
        }
    }
}

/// Encrypts a plaintext using the RC5 cipher 
///
/// Examples 
///
/// ```
/// use rc5_test::encode;
/// use rc5_test::Config;
///
/// let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
/// let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
/// let ct  = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
/// let config = Config::new(32,12,key.len());
///
/// let res = encode(key, pt, config);
///
/// assert!(&ct[..] == &res[..]);
/// ```
pub fn encode(key: Vec<u8>, plaintext: Vec<u8>, config:Config) -> Vec<u8> {
    match config.w {
        8 => return encode_8(key, plaintext, &config),
        16 => return encode_16(key, plaintext, &config),
        32 => return encode_32(key, plaintext, &config),
        64 => return encode_64(key, plaintext, &config),
        _ => panic!("Invalid word length")
    }
}

/// Decrypts a ciphertext using the RC5 cipher 
///
/// Examples 
///
/// ```
/// use rc5_test::decode;
/// use rc5_test::Config;
///
/// let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
/// let pt  = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
/// let ct  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
/// let config = Config::new(32,12,key.len());
///
/// let res = decode(key, ct, config);
///
/// assert!(&pt[..] == &res[..]);
///```
pub fn decode(key: Vec<u8>, ciphertext: Vec<u8>, config:Config) -> Vec<u8> {
    match config.w {
        8 => return decode_8(key, ciphertext, &config),
        16 => return decode_16(key, ciphertext, &config),
        32 => return decode_32(key, ciphertext, &config),
        64 => return decode_64(key, ciphertext, &config),
        _ => panic!("Invalid word length")
    }
}

// Helper functions

// 
// Key expansion functions for 8, 16, 32 and 64 bits word lengths
//
fn expand_key_8(key: Vec<u8>, config: &Config) -> Vec<u8> {
    // create local constants
    let p:u8 = 0xB7;
    let q:u8 = 0x9F;
    let t = 2*(config.r +1);
    let u = config.w / 8;

    // Converting the secret key from bytes to words
    let c = cmp::max(config.b, 1) / u;
    let mut l: Vec<u8> = vec![0;c];
    for i in (0..config.b).rev() {
        l[(i/u)] =  key[i] as u8;
    }
    // Initializing the array s
    let mut s: Vec<u8> = Vec::with_capacity(t);
    s.push(p);
    for i in 1..t {
        s.push(s[i-1].wrapping_add(q));
    }
    
    // Mixing in the secret key
    let (mut i, mut j, mut a, mut b) = (0, 0, 0, 0) ;
    for _ in 0..3*cmp::max(c, t) {
        s[i] = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
        a = s[i];
        l[j] = l[j].wrapping_add(a).wrapping_add(b).rotate_left(a.wrapping_add(b) as u32);
        b = l[j];
        i = (i + 1) % t; 
        j = (j + 1) % c; 
    }
    s
}

fn expand_key_16(key: Vec<u8>, config: &Config) -> Vec<u16> {
    // create local constants
    let p:u16 = 0xB7E1;
    let q:u16 = 0x9E37;
    let t = 2*(config.r +1);
    let u = config.w / 8;

    // Converting the secret key from bytes to words
    let c = cmp::max(config.b, 1) / u;
    let mut l: Vec<u16> = vec![0;c+1];
    for i in (0..config.b).rev() {
        l[(i/u)] = (l[(i/u)] << 8) + key[i] as u16;
    }
    // Initializing the array s
    let mut s: Vec<u16> = Vec::with_capacity(t);
    s.push(p);
    for i in 1..t {
        s.push(s[i-1].wrapping_add(q));
    }
    
    // Mixing in the secret key
    let (mut i, mut j, mut a, mut b) = (0, 0, 0, 0) ;
    for _ in 0..3*cmp::max(c, t) {
        s[i] = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
        a = s[i];
        l[j] = l[j].wrapping_add(a).wrapping_add(b).rotate_left(a.wrapping_add(b) as u32);
        b = l[j];
        i = (i + 1) % t; 
        j = (j + 1) % c; 
    }
    s
}

fn expand_key_32(key: Vec<u8>, config:&Config) -> Vec<u32> {
    // create local constants
    let p:u32 = 0xB7E15163;
    let q:u32 = 0x9E3779B9;
    let t = 2*(config.r +1);
    let u = config.w / 8;

    // Converting the secret key from bytes to words
    let c = cmp::max(config.b, 1) / u;
    let mut l: Vec<u32> = vec![0;c+1];
    for i in (0..config.b).rev() {
        l[(i/u)] = (l[(i/u)] << 8) + key[i] as u32;
    }
    // Initializing the array s
    let mut s: Vec<u32> = Vec::with_capacity(t);
    s.push(p);
    for i in 1..t {
        s.push(s[i-1].wrapping_add(q));
    }
    
    // Mixing in the secret key
    let (mut i, mut j, mut a, mut b) = (0, 0, 0, 0) ;
    for _ in 0..3*cmp::max(c, t) {
        s[i] = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
        a = s[i];
        l[j] = l[j].wrapping_add(a).wrapping_add(b).rotate_left(a.wrapping_add(b));
        b = l[j];
        i = (i + 1) % t; 
        j = (j + 1) % c; 
    }
    s
}

fn expand_key_64(key: Vec<u8>, config:&Config) -> Vec<u64> {
    // create local constants
    let p:u64 = 0xB7E151628AED2A6B;
    let q:u64 = 0x9E3779B97F4A7C15;
    let t = 2*(config.r +1);
    let u = config.w / 8;

    // Converting the secret key from bytes to words
    let c = cmp::max(config.b, 1) / u;
    let mut l: Vec<u64> = vec![0;c+1];
    for i in (0..config.b).rev() {
        l[(i/u)] = (l[(i/u)] << 8) + key[i] as u64;
    }
    // Initializing the array s
    let mut s: Vec<u64> = Vec::with_capacity(t);
    s.push(p);
    for i in 1..t {
        s.push(s[i-1].wrapping_add(q));
    }
    
    // Mixing in the secret key
    let (mut i, mut j, mut a, mut b) = (0, 0, 0, 0) ;
    for _ in 0..3*cmp::max(c, t) {
        s[i] = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
        a = s[i];
        l[j] = l[j].wrapping_add(a).wrapping_add(b).rotate_left(a.wrapping_add(b) as u32);
        b = l[j];
        i = (i + 1) % t; 
        j = (j + 1) % c; 
    }
    s
}

// 
// Encryption functions for 8, 16, 32 and 64 bits word lengths
//
fn encode_8(key: Vec<u8>, mut plaintext: Vec<u8>, config:&Config) -> Vec<u8> {
    let key = expand_key_8(key, config);
    let word_b = config.w / 8;
    for _ in 0..plaintext.len() % (word_b*2) { 
        plaintext.push(0);
    }
    plaintext
        .par_chunks_exact_mut(word_b*2)
        .for_each(|slice| {
            let mut a = u8::from_le_bytes(slice[..word_b].try_into().unwrap());
            let mut b = u8::from_le_bytes(slice[word_b..].try_into().unwrap());
            a = a.wrapping_add(key[0]);
            b = b.wrapping_add(key[1]);
            for i in 1..config.r + 1 {
                a = (a ^ b).rotate_left(b as u32).wrapping_add(key[2*i]);
                b = (b ^ a).rotate_left(a as u32).wrapping_add(key[2*i + 1]);
            }
            let a = [a.to_le_bytes(), b.to_le_bytes()].concat();
            for (i,element) in a.iter().enumerate(){
                slice[i] = *element;
            }
    });
    plaintext
}

fn encode_16(key: Vec<u8>, mut plaintext: Vec<u8>, config:&Config) -> Vec<u8> {
    let key = expand_key_16(key, config);
    let word_b = config.w / 8;
    for _ in 0..plaintext.len() % (word_b*2) { 
        plaintext.push(0);
    }
    plaintext
        .par_chunks_exact_mut(word_b*2)
        .for_each(|slice| {
            let mut a = u16::from_le_bytes(slice[..word_b].try_into().unwrap());
            let mut b = u16::from_le_bytes(slice[word_b..].try_into().unwrap());
            a = a.wrapping_add(key[0]);
            b = b.wrapping_add(key[1]);
            for i in 1..config.r + 1 {
                a = (a ^ b).rotate_left(b as u32).wrapping_add(key[2*i]);
                b = (b ^ a).rotate_left(a as u32).wrapping_add(key[2*i + 1]);
            }
            let a = [a.to_le_bytes(), b.to_le_bytes()].concat();
            for (i,element) in a.iter().enumerate(){
                slice[i] = *element;
            }
    });
    plaintext
}

fn encode_32(key: Vec<u8>, mut plaintext: Vec<u8>, config:&Config) -> Vec<u8> {
    let key = expand_key_32(key, config);
    let word_b = config.w / 8;
    for _ in 0..plaintext.len() % (word_b*2) { 
        plaintext.push(0);
    }
    plaintext
        .par_chunks_exact_mut(word_b*2)
        .for_each(|slice| {
            let mut a = u32::from_le_bytes(slice[..word_b].try_into().unwrap());
            let mut b = u32::from_le_bytes(slice[word_b..].try_into().unwrap());
            a = a.wrapping_add(key[0]);
            b = b.wrapping_add(key[1]);
            for i in 1..config.r + 1 {
                a = (a ^ b).rotate_left(b as u32).wrapping_add(key[2*i]);
                b = (b ^ a).rotate_left(a as u32).wrapping_add(key[2*i + 1]);
            }
            let a = [a.to_le_bytes(), b.to_le_bytes()].concat();
            for (i,element) in a.iter().enumerate(){
                slice[i] = *element;
            }
    });
    plaintext
}

fn encode_64(key: Vec<u8>, mut plaintext: Vec<u8>, config:&Config) -> Vec<u8> {
    let key = expand_key_64(key, config);
    let word_b = config.w / 8;
    for _ in 0..plaintext.len() % (word_b*2) { 
        plaintext.push(0);
    }
    plaintext
        .par_chunks_exact_mut(word_b*2)
        .for_each(|slice| {
            let mut a = u64::from_le_bytes(slice[..word_b].try_into().unwrap());
            let mut b = u64::from_le_bytes(slice[word_b..].try_into().unwrap());
            a = a.wrapping_add(key[0]);
            b = b.wrapping_add(key[1]);
            for i in 1..config.r + 1 {
                a = (a ^ b).rotate_left(b as u32).wrapping_add(key[2*i]);
                b = (b ^ a).rotate_left(a as u32).wrapping_add(key[2*i + 1]);
            }
            let a = [a.to_le_bytes(), b.to_le_bytes()].concat();
            for (i,element) in a.iter().enumerate(){
                slice[i] = *element;
            }
    });
    plaintext
}


// 
// Decryption functions for 8, 16, 32 and 64 bits word lengths
//
fn decode_8(key: Vec<u8>, mut ciphertext: Vec<u8>, config:&Config) -> Vec<u8> {
    let key_exp = expand_key_8(key, config);
    let word_b = config.w / 8;
    ciphertext
        .par_chunks_exact_mut(word_b*2)
        .for_each(|slice| {
            let mut a = u8::from_le_bytes(slice[..word_b].try_into().unwrap());
            let mut b = u8::from_le_bytes(slice[word_b..].try_into().unwrap());

            for i in (1..config.r + 1).rev() {
                b = (b.wrapping_sub(key_exp[2*i + 1]).rotate_right(a as u32)) ^ a;
                a = (a.wrapping_sub(key_exp[2*i]).rotate_right(b as u32)) ^ b;
            }
            b = b.wrapping_sub(key_exp[1]);
            a = a.wrapping_sub(key_exp[0]);
            
            let a = [a.to_le_bytes(), b.to_le_bytes()].concat();
            for (i,element) in a.iter().enumerate(){
                slice[i] = *element;
            }
    });
    ciphertext
}

fn decode_16(key: Vec<u8>, mut ciphertext: Vec<u8>, config:&Config) -> Vec<u8> {
    let key_exp = expand_key_16(key, config);
    let word_b = config.w / 8;
    ciphertext
        .par_chunks_exact_mut(word_b*2)
        .for_each(|slice| {
            let mut a = u16::from_le_bytes(slice[..word_b].try_into().unwrap());
            let mut b = u16::from_le_bytes(slice[word_b..].try_into().unwrap());

            for i in (1..config.r + 1).rev() {
                b = (b.wrapping_sub(key_exp[2*i + 1]).rotate_right(a as u32)) ^ a;
                a = (a.wrapping_sub(key_exp[2*i]).rotate_right(b as u32)) ^ b;
            }
            b = b.wrapping_sub(key_exp[1]);
            a = a.wrapping_sub(key_exp[0]);
            
            let a = [a.to_le_bytes(), b.to_le_bytes()].concat();
            for (i,element) in a.iter().enumerate(){
                slice[i] = *element;
            }
    });
    ciphertext
}

fn decode_32(key: Vec<u8>, mut ciphertext: Vec<u8>, config:&Config) -> Vec<u8> {
    let key_exp = expand_key_32(key, config);
    let word_b = config.w / 8;
    ciphertext
        .par_chunks_exact_mut(word_b*2)
        .for_each(|slice| {
            let mut a = u32::from_le_bytes(slice[..word_b].try_into().unwrap());
            let mut b = u32::from_le_bytes(slice[word_b..].try_into().unwrap());

            for i in (1..config.r + 1).rev() {
                b = (b.wrapping_sub(key_exp[2*i + 1]).rotate_right(a as u32)) ^ a;
                a = (a.wrapping_sub(key_exp[2*i]).rotate_right(b as u32)) ^ b;
            }
            b = b.wrapping_sub(key_exp[1]);
            a = a.wrapping_sub(key_exp[0]);
            
            let a = [a.to_le_bytes(), b.to_le_bytes()].concat();
            for (i,element) in a.iter().enumerate(){
                slice[i] = *element;
            }
    });
    ciphertext
}

fn decode_64(key: Vec<u8>, mut ciphertext: Vec<u8>, config:&Config) -> Vec<u8> {
    let key_exp = expand_key_64(key, config);
    let word_b = config.w / 8;
    ciphertext
        .par_chunks_exact_mut(word_b*2)
        .for_each(|slice| {
            let mut a = u64::from_le_bytes(slice[..word_b].try_into().unwrap());
            let mut b = u64::from_le_bytes(slice[word_b..].try_into().unwrap());

            for i in (1..config.r + 1).rev() {
                b = (b.wrapping_sub(key_exp[2*i + 1]).rotate_right(a as u32)) ^ a;
                a = (a.wrapping_sub(key_exp[2*i]).rotate_right(b as u32)) ^ b;
            }
            b = b.wrapping_sub(key_exp[1]);
            a = a.wrapping_sub(key_exp[0]);
            
            let a = [a.to_le_bytes(), b.to_le_bytes()].concat();
            for (i,element) in a.iter().enumerate(){
                slice[i] = *element;
            }
    });
    ciphertext
}


// 
// Tests cases for various combinations of RC5 parameters 
// 

#[cfg(test)]
mod tests {
	use super::*;

    // RC5-32/12/16
    #[test]
    fn encode_a() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    	let ct  = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        let config = Config::new(32,12,key.len());
    	let res = encode(key, pt, config);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_b() {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
    	let ct  = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let config = Config::new(32,12,key.len());
    	let res = encode(key, pt, config);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_a() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
    	let ct  = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let config = Config::new(32,12,key.len());
    	let res = decode(key, ct, config);
    	assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
    	let key = vec![0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48];
    	let pt  = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
    	let ct  = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let config = Config::new(32,12,key.len());
    	let res = decode(key, ct, config);
    	assert!(&pt[..] == &res[..]);
    }

    // RC5-8/12/4
    #[test]
    fn encode_c() {
    	let key = vec![0x00, 0x01, 0x02, 0x03];
    	let pt  = vec![0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01];
    	let ct  = vec![0x21, 0x2A, 0x21, 0x2A, 0x21, 0x2A, 0x21, 0x2A, 0x21, 0x2A, 0x21, 0x2A, 0x21, 0x2A];
        let config = Config::new(8,12,key.len());
    	let res = encode(key, pt, config);
        print!("res: {:?},\n ct: {:?}", res, ct);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_c() {
    	let key = vec![0x00, 0x01, 0x02, 0x03];
    	let pt  = vec![0x00, 0x01];
    	let ct  = vec![0x21, 0x2A];
        let config = Config::new(8,12,key.len());
    	let res = decode(key, ct, config);
    	assert!(&pt[..] == &res[..]);
    }

    // RC5-16/16/8
    #[test]
    fn encode_d() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    	let pt  = vec![0x00, 0x01, 0x02, 0x03];
    	let ct  = vec![0x23, 0xA8, 0xD7, 0x2E];
        let config = Config::new(16,16,key.len());
    	let res = encode(key, pt, config);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_d() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    	let pt  = vec![0x00, 0x01, 0x02, 0x03];
    	let ct  = vec![0x23, 0xA8, 0xD7, 0x2E];
        let config = Config::new(16,16,key.len());
    	let res = decode(key, ct, config);
    	assert!(&pt[..] == &res[..]);
    }
       
    // RC5-32/20/16
    #[test]
    fn encode_e() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    	let ct  = vec![0x2A, 0x0E, 0xDC, 0x0E, 0x94, 0x31, 0xFF, 0x73];
        let config = Config::new(32,20,key.len());
    	let res = encode(key, pt, config);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_e() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let pt  = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    	let ct  = vec![0x2A, 0x0E, 0xDC, 0x0E, 0x94, 0x31, 0xFF, 0x73];
        let config = Config::new(32,20,key.len());
    	let res = decode(key, ct, config);
    	assert!(&pt[..] == &res[..]);
    }

    // RC5-64/24/24
    #[test]
    fn encode_f() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    	let pt  = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let ct  = vec![0xA4, 0x67, 0x72, 0x82, 0x0E, 0xDB, 0xCE, 0x02, 0x35, 0xAB, 0xEA, 0x32, 0xAE, 0x71, 0x78, 0xDA];
        let config = Config::new(64,24,key.len());
    	let res = encode(key, pt, config);
    	assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_f() {
    	let key = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
    	let pt  = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    	let ct  = vec![0xA4, 0x67, 0x72, 0x82, 0x0E, 0xDB, 0xCE, 0x02, 0x35, 0xAB, 0xEA, 0x32, 0xAE, 0x71, 0x78, 0xDA];
        let config = Config::new(64,24,key.len());
    	let res = decode(key, ct, config);
    	assert!(&pt[..] == &res[..]);
    }
}

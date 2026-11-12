use rand::RngCore;

pub type Sid = [u8; 16];
pub type Token = [u8; 32];

pub fn fresh_sid() -> Sid {
    let mut s = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut s);
    s
}

pub fn fresh_token() -> Token {
    let mut t = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut t);
    t
}

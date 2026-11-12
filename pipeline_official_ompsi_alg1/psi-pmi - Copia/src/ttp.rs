use crate::sig::Ed25519Signer;
use crate::types::Sid;
use curve25519_dalek::ristretto::RistrettoPoint;

pub const DOM_SIGMA: &[u8] = b"PSI-PMI/v1/TTP/sigma";
pub const DOM_T: &[u8]     = b"PSI-PMI/v1/TTP/T";
pub const DOM_EVAL: &[u8]  = b"PSI-PMI/v1/S1/eval";

pub fn sigma_msg(sid: &Sid, sigma: usize) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DOM_SIGMA);
    m.extend_from_slice(sid);
    m.extend_from_slice(&(sigma as u64).to_le_bytes());
    m
}

pub fn t_msg(sid: &Sid, t: &RistrettoPoint) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DOM_T);
    m.extend_from_slice(sid);
    m.extend_from_slice(&t.compress().to_bytes());
    m
}

pub fn eval_msg(sid: &Sid, e_b_bytes: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DOM_EVAL);
    m.extend_from_slice(sid);
    m.extend_from_slice(e_b_bytes);
    m
}

pub struct Ttp { pub signer: Ed25519Signer }

impl Ttp {
    pub fn new() -> Self { Self { signer: Ed25519Signer::generate() } }
}

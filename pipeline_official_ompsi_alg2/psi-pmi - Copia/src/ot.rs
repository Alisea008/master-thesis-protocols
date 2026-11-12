use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::Rng;
use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256};

use crate::{Error, Result};

pub const TAG_BITS: usize = 48;

fn h_ct(k: &RistrettoPoint, j: usize, out_len: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(b"PSI-PMI/OT/Hct/v1");
    h.update(&k.compress().to_bytes());
    h.update(&(j as u64).to_le_bytes());
    let mut r = h.finalize_xof();
    let mut buf = vec![0u8; out_len];
    r.read(&mut buf);
    buf
}

fn h_tag(k: &RistrettoPoint, j: usize) -> Vec<u8> {
    let mut h = Shake256::default();
    h.update(b"PSI-PMI/OT/Htag/v1");
    h.update(&k.compress().to_bytes());
    h.update(&(j as u64).to_le_bytes());
    let mut r = h.finalize_xof();
    let n = (TAG_BITS + 7) / 8;
    let mut buf = vec![0u8; n];
    r.read(&mut buf);
    let extra = n * 8 - TAG_BITS;
    if extra > 0 { buf[n - 1] &= 0xffu8 >> extra; }
    buf
}

fn point_from_bytes(b: &[u8]) -> Result<RistrettoPoint> {
    let arr: [u8; 32] = b.try_into().map_err(|_| Error::Invalid("point len".into()))?;
    CompressedRistretto(arr).decompress()
        .ok_or_else(|| Error::Invalid("invalid ristretto point".into()))
}

pub struct OtDoState {
    pub r: Scalar,
    pub c: Vec<RistrettoPoint>,
    pub u: usize,
}

impl Drop for OtDoState {
    fn drop(&mut self) {
        // A3: wipe the OT scalar r on drop. The points `c` are public.
        use zeroize::Zeroize;
        self.r.zeroize();
    }
}

pub struct OtPhase1Msg {
    pub c: Vec<Vec<u8>>,
    pub g_r: Vec<u8>,
}

pub fn ot_phase1(
    u: usize,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> (OtDoState, OtPhase1Msg) { 
    assert!(u >= 1);
    let r = Scalar::random(rng);
    let mut c = Vec::with_capacity(u);
    c.push(RISTRETTO_BASEPOINT_POINT);
    for _ in 1..u { c.push(RistrettoPoint::random(rng)); }
    let g_r = (RISTRETTO_BASEPOINT_POINT * r).compress().to_bytes().to_vec();
    let c_ser: Vec<Vec<u8>> = c[1..].iter().map(|p| p.compress().to_bytes().to_vec()).collect();
    (OtDoState { r, c, u }, OtPhase1Msg { c: c_ser, g_r })
}

pub struct OtTtpOutput {
    pub pk0_bytes: Vec<u8>,
    pub t: RistrettoPoint,
    pub sigma: usize,
}

pub fn ot_phase2(
    u: usize,
    phase1: &OtPhase1Msg,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<OtTtpOutput> {
    let sigma = rng.gen_range(0..u);
    ot_phase2_with_sigma(u, phase1, sigma, rng)
}

pub fn ot_phase2_with_sigma(
    u: usize,
    phase1: &OtPhase1Msg,
    sigma: usize,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
) -> Result<OtTtpOutput> {
    assert!(sigma < u);
    let _ = u;
    let k = Scalar::random(rng);
    let g_r = point_from_bytes(&phase1.g_r)?;
    let t = g_r * k;
    let pk_sigma = RISTRETTO_BASEPOINT_POINT * k;

    let pk0 = if sigma == 0 {
        pk_sigma
    } else {
        let c_sigma = point_from_bytes(&phase1.c[sigma - 1])?;
        c_sigma - pk_sigma
    };

    Ok(OtTtpOutput {
        pk0_bytes: pk0.compress().to_bytes().to_vec(),
        t,
        sigma,
    })
}

#[derive(Clone)]
pub struct OtCiphertext {
    pub ct: Vec<u8>,
    pub tag: Vec<u8>,
}

pub fn ot_phase3(
    state: &OtDoState,
    pk0_bytes: &[u8],
    messages: &[Vec<u8>],
) -> Result<Vec<OtCiphertext>> {
    assert_eq!(messages.len(), state.u);
    let pk0 = point_from_bytes(pk0_bytes)?;
    let k0 = pk0 * state.r;
    let mut out = Vec::with_capacity(state.u);

    {
        let mut ct = h_ct(&k0, 0, messages[0].len());
        for (a, b) in ct.iter_mut().zip(&messages[0]) { *a ^= b; }
        out.push(OtCiphertext { ct, tag: h_tag(&k0, 0) });
    }

    for j in 1..state.u {
        let k_j = state.c[j] * state.r - k0;
        let mut ct = h_ct(&k_j, j, messages[j].len());
        for (a, b) in ct.iter_mut().zip(&messages[j]) { *a ^= b; }
        out.push(OtCiphertext { ct, tag: h_tag(&k_j, j) });
    }
    Ok(out)
}

pub fn ot_phase4(t: &RistrettoPoint, cts: &[OtCiphertext]) -> Result<(usize, Vec<u8>)> {
    let mut found: Option<usize> = None;
    let mut matches = 0usize;
    for (j, c) in cts.iter().enumerate() {
        if h_tag(t, j) == c.tag {
            matches += 1;
            if found.is_none() {
                found = Some(j);
            }
        }
    }
    if matches > 1 {
        eprintln!(
            "[ot_phase4] WARNING: {} tag collisions (tag_bits={}); using first match",
            matches, TAG_BITS
        );
    }
    let j = found.ok_or_else(|| Error::Protocol("no tag match".into()))?;
    let mut m = h_ct(t, j, cts[j].ct.len());
    for (a, b) in m.iter_mut().zip(&cts[j].ct) {
        *a ^= b;
    }
    Ok((j, m))
}
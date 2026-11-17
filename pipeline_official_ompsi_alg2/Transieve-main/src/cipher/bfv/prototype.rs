use anyhow::Result;
use fhe::bfv::{
    BfvParametersBuilder, Ciphertext, Encoding, EvaluationKeyBuilder, Plaintext, SecretKey,
};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};

fn anyize<E: std::fmt::Debug>(e: E) -> anyhow::Error {
    anyhow::anyhow!("fhe error: {e:?}")
}

#[derive(Debug)]
pub struct DemoReport {
    pub slots: usize,

    pub taps: Vec<usize>,

    pub matched: bool,

    pub rotations_ok: bool,
}

const PLAINTEXT_MODULUS: u64 = 65537;
const DEGREE: usize = 4096;

fn encrypt_slots<R: rand_bfv::RngCore + rand_bfv::CryptoRng>(
    params: &std::sync::Arc<fhe::bfv::BfvParameters>,
    sk: &SecretKey,
    rng: &mut R,
    data: &[u64],
) -> Result<Ciphertext> {
    let pt = Plaintext::try_encode(data, Encoding::simd(), params).map_err(anyize)?;
    let ct: Ciphertext = sk.try_encrypt(&pt, rng).map_err(anyize)?;
    Ok(ct)
}

fn decrypt_slots(sk: &SecretKey, ct: &Ciphertext) -> Result<Vec<u64>> {
    let pt = sk.try_decrypt(ct).map_err(anyize)?;
    let v = Vec::<u64>::try_decode(&pt, Encoding::simd()).map_err(anyize)?;
    Ok(v)
}

pub fn run_linear_layer_demo() -> Result<DemoReport> {
    let params = BfvParametersBuilder::new()
        .set_degree(DEGREE)
        .set_plaintext_modulus(PLAINTEXT_MODULUS)
        .set_moduli_sizes(&[60, 60])
        .build_arc()
        .map_err(anyize)?;

    let mut rng = rand_bfv::rng();
    let sk = SecretKey::random(&params, &mut rng);

    let taps = vec![1usize, 2usize];
    let mut ekb = EvaluationKeyBuilder::new(&sk).map_err(anyize)?;
    for &s in &taps {
        ekb.enable_column_rotation(s).map_err(anyize)?;
    }
    let ek = ekb.build(&mut rng).map_err(anyize)?;

    let slots = DEGREE;

    let idx: Vec<u64> = (0..slots as u64).collect();
    let idx_ct = encrypt_slots(&params, &sk, &mut rng, &idx)?;
    let mut perms: Vec<Vec<usize>> = Vec::with_capacity(taps.len());
    let mut rotations_ok = true;
    for &s in &taps {
        let rot = ek.rotates_columns_by(&idx_ct, s).map_err(anyize)?;
        let learned = decrypt_slots(&sk, &rot)?;

        let mut seen = vec![false; slots];
        for &p in &learned {
            let p = p as usize;
            if p >= slots || seen[p] {
                rotations_ok = false;
                break;
            }
            seen[p] = true;
        }
        perms.push(learned.iter().map(|&p| p as usize).collect());
    }

    let v: Vec<u64> = (0..slots as u64)
        .map(|j| (j.wrapping_mul(7).wrapping_add(3)) % 101)
        .collect();
    let v_ct = encrypt_slots(&params, &sk, &mut rng, &v)?;

    let mut acc = v_ct.clone();
    for &s in &taps {
        let r = ek.rotates_columns_by(&v_ct, s).map_err(anyize)?;
        acc = &acc + &r;
    }
    let y = decrypt_slots(&sk, &acc)?;

    let mut y_exp = vec![0u64; slots];
    for j in 0..slots {
        let mut s = v[j];
        for perm in &perms {
            s = (s + v[perm[j]]) % PLAINTEXT_MODULUS;
        }
        y_exp[j] = s;
    }

    let matched = y == y_exp;

    Ok(DemoReport {
        slots,
        taps,
        matched,
        rotations_ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bfv_rotate_and_add_linear_layer_matches_plaintext() {
        let report = run_linear_layer_demo().expect("BFV prototype failed to run");
        println!(
            "[BFV prototype] slots={}, taps={:?}, rotations_ok={}, matched={}",
            report.slots, report.taps, report.rotations_ok, report.matched
        );
        assert!(
            report.rotations_ok,
            "a learned rotation was not a valid slot permutation"
        );
        assert!(
            report.matched,
            "homomorphic rotate-and-add did not match the plaintext oracle"
        );
    }
}

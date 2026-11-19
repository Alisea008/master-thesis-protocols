use psi_pmi::pasta_fhe::{PastaFhe, TransievePasta};
use psi_pmi::sim::pasta_sim;
use transieve::cipher::bfv::pasta::PASTA3;

fn main() -> anyhow::Result<()> {
    let params = PASTA3;
    let t = params.t;
    let k_sym = vec![42u8; 32];
    let nonce = [3u64, 0u64];

    let fhe = TransievePasta::default();
    let ctx = fhe.setup(0)?;               // nessun AND, quindi 0 livelli SOP
    let key_ct = fhe.pack_key(&ctx, &k_sym)?;

    let mut all_ok = true;
    for &n_bits in &[128usize, 129, 367, 384, 2048] {
        let bits: Vec<u8> = (0..n_bits)
            .map(|i| (((i as u64).wrapping_mul(2654435761) >> 7) & 1) as u8)
            .collect();

        let blocks = pasta_sim::enc_blocks(&bits, &k_sym, nonce, params);
        let nb = blocks.len();
        let words: Vec<Vec<u64>> = blocks.iter().map(|b| pasta_sim::bytes_to_words(b)).collect();
        let ids: Vec<u64> = (0..nb as u64).collect();

        let ct = fhe.transcipher(&ctx, &key_ct, nonce, &ids, &words)?;
        let dec = fhe.decrypt_bits(&ctx, &ct, n_bits)?;
        assert_eq!(dec.len(), n_bits);

        let mut per_block = vec![0usize; nb];
        for i in 0..n_bits {
            if dec[i] != (bits[i] == 1) { per_block[i / t] += 1; }
        }
        let bad: usize = per_block.iter().sum();
        println!("n_bits={n_bits:5} blocks={nb:2} mismatch={bad} per_block={per_block:?}");
        all_ok &= bad == 0;
    }
    println!("{}", if all_ok { "OK" } else { "FAIL" });
    Ok(())
}
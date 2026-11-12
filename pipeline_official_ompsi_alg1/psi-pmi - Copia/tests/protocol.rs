use psi_pmi::bloom::{BloomFilter, Family};
use psi_pmi::ot::{ot_phase1, ot_phase2, ot_phase3, ot_phase4};

#[test]
fn bloom_no_false_negatives() {
    let seed = [7u8; 32];
    let f = Family::new(seed, 3);
    let mut bf = BloomFilter::new(8192);
    let items: Vec<Vec<u8>> = (0..200u32).map(|i| i.to_le_bytes().to_vec()).collect();
    for x in &items { bf.insert(x, &f); }
    for x in &items { assert!(bf.contains(x, &f)); }
}

#[test]
fn ot_all_sigmas() {
    let u = 4;
    let messages: Vec<Vec<u8>> = (0..u).map(|i| vec![i as u8; 64]).collect();
    for _ in 0..20 {
        let mut rng = rand::thread_rng();
        let (state, p1) = ot_phase1(u, &mut rng);
        let ttp_out = ot_phase2(u, &p1, &mut rng).unwrap();
        let cts = ot_phase3(&state, &ttp_out.pk0_bytes, &messages).unwrap();
        let (j, m) = ot_phase4(&ttp_out.t, &cts).unwrap();
        assert_eq!(j, ttp_out.sigma);
        assert_eq!(m, messages[ttp_out.sigma]);
    }
}

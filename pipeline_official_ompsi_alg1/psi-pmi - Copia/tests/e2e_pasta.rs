//! Test end-to-end con BFV+Pasta-3. Degree 8192 = veloce, NON 128-bit safe.

use psi_pmi::psi::{run_e2e_pasta, DataOwnerInput, E2eConfig};
use transieve::cipher::bfv::pasta::PASTA3;

fn seed(i: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (j, b) in s.iter_mut().enumerate() {
        *b = i.wrapping_add(j as u8);
    }
    s
}

fn cfg() -> E2eConfig {
    E2eConfig {
        u: 4,
        n_bits: 128,
        hash_k: 3,
        seeds: vec![seed(1), seed(2), seed(3), seed(4)],
    }
}

fn do_input(names: &[&[u8]], k: u8) -> DataOwnerInput {
    DataOwnerInput {
        elements: names.iter().map(|n| n.to_vec()).collect(),
        k_sym: vec![k; 32],
    }
}

#[test]
fn e2e_n2_pasta3() {
    let do1 = do_input(&[b"alice", b"bob", b"carol"], 7);
    let do2 = do_input(&[b"bob", b"carol", b"dave"], 9);
    let res = run_e2e_pasta(PASTA3, Some(8192), &cfg(), vec![do1, do2])
        .expect("n=2 must succeed");

    assert_eq!(res.do1_out.len(), 3);
    assert!(res.sigma < 4);

    for name in [b"bob".as_slice(), b"carol".as_slice()] {
        let e = res.do1_out.iter().find(|(x, _)| x == name).unwrap();
        assert_ne!(
            e.1,
            [0u8; 32],
            "{} must be in intersection",
            String::from_utf8_lossy(name)
        );
    }
    let alice = res.do1_out.iter().find(|(x, _)| x == b"alice").unwrap();
    assert_eq!(alice.1, [0u8; 32], "alice must be outside");
}

#[test]
fn e2e_n3_pasta3() {
    // 3 DO, intersezione = {"bob"} (presente in tutti e 3)
    let do1 = do_input(&[b"alice", b"bob", b"carol"], 7);
    let do2 = do_input(&[b"bob", b"carol", b"dave"], 9);
    let do3 = do_input(&[b"bob", b"eve", b"frank"], 11);

    let res = run_e2e_pasta(PASTA3, Some(8192), &cfg(), vec![do1, do2, do3])
        .expect("n=3 must succeed");

    let bob = res.do1_out.iter().find(|(x, _)| x == b"bob").unwrap();
    assert_ne!(bob.1, [0u8; 32], "bob must be in 3-way intersection");

    let alice = res.do1_out.iter().find(|(x, _)| x == b"alice").unwrap();
    assert_eq!(alice.1, [0u8; 32], "alice is only in DO_1");
}
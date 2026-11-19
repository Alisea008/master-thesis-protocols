//! End-to-end test of the alternative protocol (Algorithm 2, no TEE, simulated CMUX).
//! Multi-block: n_bits can exceed 128.

use psi_pmi::psi::{run_e2e_pasta_alt, DataOwnerInput, E2eConfig};
use transieve::cipher::bfv::pasta::PASTA3;

// Build a deterministic 32-byte seed from a single byte
fn seed(i: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    for (j, b) in s.iter_mut().enumerate() { *b = i.wrapping_add(j as u8); }
    s
}

// Single-block test configuration: n_bits = 128 == t, so exactly one block
fn cfg() -> E2eConfig {
    E2eConfig {
        u: 4,
        n_bits: 128,
        hash_k: 3,
        seeds: vec![seed(1), seed(2), seed(3), seed(4)],
    }
}

// Multi-block test configuration
fn cfg_ml() -> E2eConfig {
    // n_bits > t: forces multi-block for filters and index matrix.
    E2eConfig {
        u: 4,
        n_bits: 200,
        hash_k: 3,
        seeds: vec![seed(1), seed(2), seed(3), seed(4)],
    }
}

// Build a DataOwnerInput from string elements with a fixed symmetric key byte
fn do_input(names: &[&[u8]], k: u8) -> DataOwnerInput {
    DataOwnerInput {
        elements: names.iter().map(|n| n.to_vec()).collect(),
        k_sym: vec![k; 32],
    }
}

#[test]
fn e2e_alt_n2_pasta3() {
    let do1 = do_input(&[b"alice", b"bob", b"carol"], 7);
    let do2 = do_input(&[b"bob", b"carol", b"dave"], 9);
    let res = run_e2e_pasta_alt(PASTA3, Some(8192), &cfg(), vec![do1, do2])
        .expect("alt n=2 must succeed");

    // DO_1 contributes three elements
    assert_eq!(res.do1_out.len(), 3);
    // σ must be one of the valid OT choices
    assert!(res.sigma < 4);
    // With n_bits=128 and t=128, only one filter block is needed
    assert_eq!(res.n_b_blocks, 1);

    // Elements present in both sets must carry a non-zero token
    for name in [b"bob".as_slice(), b"carol".as_slice()] {
        let e = res.do1_out.iter().find(|(x, _)| x == name).unwrap();
        assert_ne!(e.1, [0u8; 32], "{} must be in intersection (alt)", String::from_utf8_lossy(name));
    }
    // An element only in DO_1 must carry the zero token
    let alice = res.do1_out.iter().find(|(x, _)| x == b"alice").unwrap();
    assert_eq!(alice.1, [0u8; 32], "alice must be outside (alt)");
}

#[test]
fn e2e_alt_n3_pasta3() {
    let do1 = do_input(&[b"alice", b"bob", b"carol"], 7);
    let do2 = do_input(&[b"bob", b"carol", b"dave"], 9);
    let do3 = do_input(&[b"bob", b"eve", b"frank"], 11);

    let res = run_e2e_pasta_alt(PASTA3, Some(8192), &cfg(), vec![do1, do2, do3])
        .expect("alt n=3 must succeed");

    // Only "bob" is common to all three DOs
    let bob = res.do1_out.iter().find(|(x, _)| x == b"bob").unwrap();
    assert_ne!(bob.1, [0u8; 32], "bob must be in 3-way intersection (alt)");

    // "alice" appears only in DO_1
    let alice = res.do1_out.iter().find(|(x, _)| x == b"alice").unwrap();
    assert_eq!(alice.1, [0u8; 32], "alice only in DO_1 (alt)");

    // The exact intersection must be recovered with no errors
    assert_eq!(res.false_positives, 0);
    assert_eq!(res.false_negatives, 0);
}

#[test]
fn e2e_alt_no_false_negatives_larger_set() {
    let do1 = do_input(&[b"a", b"b", b"c", b"d", b"e", b"f"], 7);
    let do2 = do_input(&[b"c", b"d", b"e", b"x"], 9);
    let res = run_e2e_pasta_alt(PASTA3, Some(8192), &cfg(), vec![do1, do2])
        .expect("alt n=2 must succeed");

    // Common elements must be reported as in the intersection
    for name in [b"c".as_slice(), b"d".as_slice(), b"e".as_slice()] {
        let e = res.do1_out.iter().find(|(x, _)| x == name).unwrap();
        assert_ne!(e.1, [0u8; 32], "{} must be in", String::from_utf8_lossy(name));
    }
    // DO_1-only elements must be reported as outside
    for name in [b"a".as_slice(), b"b".as_slice(), b"f".as_slice()] {
        let e = res.do1_out.iter().find(|(x, _)| x == name).unwrap();
        assert_eq!(e.1, [0u8; 32], "{} must be out", String::from_utf8_lossy(name));
    }
    // No errors in either direction
    assert_eq!(res.false_positives, 0);
    assert_eq!(res.false_negatives, 0);
}

#[test]
fn e2e_alt_multi_block_filters() {
    // n_bits = 200 > t = 128 → n_b_blocks = 2
    let do1 = do_input(&[b"alice", b"bob", b"carol", b"dave"], 7);
    let do2 = do_input(&[b"bob", b"carol", b"eve"], 9);
    let res = run_e2e_pasta_alt(PASTA3, Some(8192), &cfg_ml(), vec![do1, do2])
        .expect("multi-block must succeed");

    // The filter must span at least two blocks, and the index matrix at least one
    assert!(res.n_b_blocks >= 2, "n_bits=200 > t=128 → n_b_blocks≥2");
    assert!(res.n_a_blocks >= 1);

    // Common elements must be in the intersection
    for name in [b"bob".as_slice(), b"carol".as_slice()] {
        let e = res.do1_out.iter().find(|(x, _)| x == name).unwrap();
        assert_ne!(e.1, [0u8; 32], "{} must be in (multi-block)", String::from_utf8_lossy(name));
    }
    // DO_1-only elements must be outside
    for name in [b"alice".as_slice(), b"dave".as_slice()] {
        let e = res.do1_out.iter().find(|(x, _)| x == name).unwrap();
        assert_eq!(e.1, [0u8; 32], "{} must be out (multi-block)", String::from_utf8_lossy(name));
    }
    // No errors
    assert_eq!(res.false_positives, 0);
    assert_eq!(res.false_negatives, 0);
}

#[test]
fn e2e_alt_multi_block_large_set() {
    // set_size=20, n_bits=500 → n_b=4, n_a is large
    let do1 = do_input(
        &[b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h", b"i", b"j",
          b"k", b"l", b"m", b"n", b"o", b"p", b"q", b"r", b"s", b"t"],
        7,
    );
    let do2 = do_input(&[b"c", b"e", b"g", b"i", b"k", b"m", b"o", b"q", b"s", b"z"], 9);
    let cfg_big = E2eConfig {
        u: 4,
        n_bits: 500,
        hash_k: 3,
        seeds: vec![seed(1), seed(2), seed(3), seed(4)],
    };
    let res = run_e2e_pasta_alt(PASTA3, Some(8192), &cfg_big, vec![do1, do2])
        .expect("multi-block large set must succeed");

    // With n_bits=500 and t=128, at least four filter blocks are needed
    assert!(res.n_b_blocks >= 4, "n_bits=500 > 3*t → n_b_blocks≥4");
    // intersection: {c, e, g, i, k, m, o, q, s}
    for name in [b"c".as_slice(), b"e".as_slice(), b"g".as_slice(), b"k".as_slice(), b"s".as_slice()] {
        let e = res.do1_out.iter().find(|(x, _)| x == name).unwrap();
        assert_ne!(e.1, [0u8; 32], "{} must be in", String::from_utf8_lossy(name));
    }
    // Elements only in DO_1 must be outside
    for name in [b"a".as_slice(), b"d".as_slice(), b"t".as_slice()] {
        let e = res.do1_out.iter().find(|(x, _)| x == name).unwrap();
        assert_eq!(e.1, [0u8; 32], "{} must be out", String::from_utf8_lossy(name));
    }
    // No errors
    assert_eq!(res.false_positives, 0);
    assert_eq!(res.false_negatives, 0);
}

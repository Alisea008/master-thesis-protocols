use siphasher::sip128::{Hasher128, SipHasher24};
use std::hash::Hasher;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct BloomFilter {
    pub bits: Vec<bool>,
    pub num_bits: usize,
    pub num_hash_funcs: usize,

    key_a: (u64, u64),
    key_b: (u64, u64),
}

impl BloomFilter {
    pub fn new(est_elements: usize, false_positive_rate: f64) -> Self {
        let (m, k) = optimal_params(est_elements, false_positive_rate);
        Self::with_params(m, k)
    }

    pub fn with_params(num_bits: usize, num_hash_funcs: usize) -> Self {
        BloomFilter {
            bits: vec![false; num_bits],
            num_bits,
            num_hash_funcs,
            key_a: (0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210),
            key_b: (0xDEAD_BEEF_CAFE_BABE, 0xBAAD_F00D_1337_C0DE),
        }
    }

    pub fn insert(&mut self, ip: &Ipv4Addr) {
        let indices: Vec<usize> = self.indices(ip).collect();
        for idx in indices {
            self.bits[idx] = true;
        }
    }

    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        self.indices(ip).all(|idx| self.bits[idx])
    }

    pub fn contains_in(&self, ip: &Ipv4Addr, bits: &[bool]) -> bool {
        assert_eq!(bits.len(), self.num_bits);
        self.indices(ip).all(|idx| bits[idx])
    }

    fn indices<'a>(&'a self, ip: &'a Ipv4Addr) -> impl Iterator<Item = usize> + 'a {
        let octets = ip.octets();
        let h1 = sip_hash(&octets, self.key_a);
        let h2 = sip_hash(&octets, self.key_b);
        let m = self.num_bits as u64;
        (0..self.num_hash_funcs as u64).map(move |i| {
            let h = h1.wrapping_add(i.wrapping_mul(h2));
            (h % m) as usize
        })
    }
}

fn sip_hash(bytes: &[u8], key: (u64, u64)) -> u64 {
    let mut hasher = SipHasher24::new_with_keys(key.0, key.1);
    hasher.write(bytes);
    let h = hasher.finish128();
    h.h1 ^ h.h2
}

pub fn optimal_params(n: usize, p: f64) -> (usize, usize) {
    let n = n.max(1) as f64;
    let p = p.clamp(f64::MIN_POSITIVE, 0.5);
    let ln2 = std::f64::consts::LN_2;
    let m = (-n * p.ln() / (ln2 * ln2)).ceil() as usize;
    let k = (((m as f64 / n) * ln2).round() as usize).max(1);
    (m, k)
}

pub fn fpr_for(party_set_size: usize) -> f64 {
    1.0 / party_set_size.max(1) as f64
}

pub fn build_party_bloom_filters(
    party_sets: &[Vec<Ipv4Addr>],
    party_set_size: usize,
    false_positive_rate: f64,
) -> Vec<BloomFilter> {
    party_sets
        .iter()
        .map(|s| {
            let mut bf = BloomFilter::new(party_set_size, false_positive_rate);
            for ip in s {
                bf.insert(ip);
            }
            bf
        })
        .collect()
}

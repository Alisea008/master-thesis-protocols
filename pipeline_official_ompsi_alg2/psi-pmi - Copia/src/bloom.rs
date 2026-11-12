use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256};

#[derive(Clone)]
pub struct Family {
    seed: [u8; 32],
    k: usize,
}

impl Family {
    pub fn new(seed: [u8; 32], k: usize) -> Self { Self { seed, k } }
    pub fn k(&self) -> usize { self.k }

    pub fn positions(&self, x: &[u8], n_bits: usize) -> Vec<usize> {
        let mut h = Shake256::default();
        h.update(b"PSI-PMI/Bloom/positions/v1");
        h.update(&self.seed);
        h.update(&(x.len() as u64).to_le_bytes());
        h.update(x);
        let mut reader = h.finalize_xof();
        let mut buf = vec![0u8; 8 * self.k];
        reader.read(&mut buf);
        buf.chunks_exact(8)
            .map(|c| {
                let v = u64::from_le_bytes(c.try_into().unwrap());
                (v as usize) % n_bits
            })
            .collect()
    }
}

#[derive(Clone)]
pub struct HashFamilies { families: Vec<Family> }

impl HashFamilies {
    pub fn new(seeds: Vec<[u8; 32]>, k: usize) -> Self {
        Self { families: seeds.into_iter().map(|s| Family::new(s, k)).collect() }
    }
    pub fn get(&self, u: usize) -> &Family { &self.families[u] }
    pub fn len(&self) -> usize { self.families.len() }
    pub fn is_empty(&self) -> bool { self.families.is_empty() }
}

#[derive(Clone, Debug)]
pub struct BloomFilter {
    n_bits: usize,
    bits: Vec<u8>,
}

impl BloomFilter {
    pub fn new(n_bits: usize) -> Self {
        assert!(n_bits % 8 == 0, "n_bits must be multiple of 8");
        Self { n_bits, bits: vec![0u8; n_bits / 8] }
    }
    pub fn n_bits(&self) -> usize { self.n_bits }
    pub fn get(&self, idx: usize) -> bool { self.bits[idx / 8] & (1 << (idx % 8)) != 0 }
    fn set(&mut self, idx: usize) { self.bits[idx / 8] |= 1 << (idx % 8); }

    pub fn insert(&mut self, x: &[u8], family: &Family) {
        for p in family.positions(x, self.n_bits) { self.set(p); }
    }

    pub fn contains(&self, x: &[u8], family: &Family) -> bool {
        family.positions(x, self.n_bits).iter().all(|&p| self.get(p))
    }

    pub fn to_packed_bytes(&self) -> Vec<u8> { self.bits.clone() }
    pub fn from_packed_bytes(bytes: Vec<u8>) -> Self {
        Self { n_bits: bytes.len() * 8, bits: bytes }
    }

    /// Espande a un bit per slot (0/1) — formato accettato dal transcipher.
    pub fn to_bit_slots(&self) -> Vec<u8> {
        (0..self.n_bits).map(|i| self.get(i) as u8).collect()
    }
}

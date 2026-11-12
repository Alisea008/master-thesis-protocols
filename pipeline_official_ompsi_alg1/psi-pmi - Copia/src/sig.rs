use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};

pub trait Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn verifying_key_bytes(&self) -> Vec<u8>;
}

pub trait Verifier {
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;
}

pub struct Ed25519Signer { key: SigningKey }

impl Ed25519Signer {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self { key: SigningKey::generate(&mut rng) }
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.key.sign(msg).to_bytes().to_vec()
    }
    fn verifying_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }
}

pub struct Ed25519Verifier { key: VerifyingKey }

impl Ed25519Verifier {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let arr: [u8; 32] = b.try_into().ok()?;
        let key = VerifyingKey::from_bytes(&arr).ok()?;
        Some(Self { key })
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(arr) = <[u8; 64]>::try_from(sig) else { return false; };
        let sig = Signature::from_bytes(&arr);
        self.key.verify(msg, &sig).is_ok()
    }
}

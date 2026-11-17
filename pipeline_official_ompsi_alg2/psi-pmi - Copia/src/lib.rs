pub mod bloom;
pub mod net;
pub mod ot;
pub mod pasta_fhe;
pub mod psi;
pub mod sig;
pub mod sim;
pub mod ttp;
pub mod types;
// NB: nessun `pub mod tee;` — Algorithm 2 non usa il TEE.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("channel: {0}")]
    Channel(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("tee abort: {0}")]
    TeeAbort(String), // mantenuto per compatibilità, non usato in Alg. 2
    #[error("fhe: {0}")]
    Fhe(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::Fhe(format!("{e:#}"))
    }
}

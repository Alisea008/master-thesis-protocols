use std::collections::{HashMap, VecDeque};

use crate::{Error, Result};

pub type PartyId = &'static str;

#[derive(Default)]
pub struct Network {
    queues: HashMap<(PartyId, PartyId), VecDeque<Vec<u8>>>,
}

impl Network {
    pub fn new() -> Self { Self::default() }
    pub fn send(&mut self, from: PartyId, to: PartyId, msg: Vec<u8>) {
        self.queues.entry((from, to)).or_default().push_back(msg);
    }
    pub fn recv(&mut self, from: PartyId, to: PartyId) -> Result<Vec<u8>> {
        self.queues
            .get_mut(&(from, to))
            .and_then(|q| q.pop_front())
            .ok_or_else(|| Error::Channel(format!("no message {from} -> {to}")))
    }
}

pub trait SecureChannel {
    fn send(&self, msg: &[u8]) -> Result<()>;
    fn recv(&self) -> Result<Vec<u8>>;
}

#[derive(Default)]
pub struct DirectChannel {
    pub queue: VecDeque<Vec<u8>>,
}

impl DirectChannel {
    pub fn new() -> Self { Self::default() }
    pub fn send(&mut self, msg: Vec<u8>) { self.queue.push_back(msg); }
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        self.queue.pop_front().ok_or_else(|| Error::Channel("direct empty".into()))
    }
}

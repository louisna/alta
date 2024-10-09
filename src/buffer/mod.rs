use std::collections::VecDeque;

use crate::Error;
use crate::Result;
use crate::State;
use crate::ALTA_A;
use crate::ALTA_P;
use crate::{PktHash, Signature};

const BUFF_SIZE: usize = ALTA_A * ALTA_P + 1;

macro_rules! index {
    ($s:expr) => {
        $s as usize % BUFF_SIZE
    };
}

/// Internal representation of an element in the Buffer.
pub struct BufferEntry {
    /// Ordered list of packet hashes.
    /// Maximum number of hashes is 5 in mode a=3,p=5.
    hashes: VecDeque<PktHash>,

    /// Optional digital signature.
    signature: Option<Signature>,

    /// Node ID.
    id: u64,

    /// Node payload.
    payload: Option<Vec<u8>>,

    /// Dependencies of the node.
    dependencies: Vec<u64>,

    /// The state of the node.
    state: State,
}

impl BufferEntry {
    /// New simple entry with an ID.
    pub fn new_id(id: u64) -> Self {
        Self {
            hashes: VecDeque::with_capacity(5),
            signature: None,
            id,
            payload: None,
            dependencies: Self::dependencies_in(id),
            state: State::NotReady,
        }
    }

    /// New entry with a payload and an ID.
    pub fn new(id: u64, payload: Vec<u8>) -> Self {
        let mut out = Self::new_id(id);
        out.payload = Some(payload);
        out
    }

    /// Get the IDs of nodes that this node must send its hash to.
    pub fn dependencies_out(&self) -> Vec<u64> {
        let id: u64 = self.id;
        match id % 5 {
            0 => [id + 5, id + 15].to_vec(),
            1 => [id - 1, id + 4].to_vec(),
            2 => [id - 1, id + 2].to_vec(),
            3 => [id - 1, id + 1].to_vec(),
            4 => [id - 3, id + 1].to_vec(),
            _ => Vec::new(),
        }
    }

    /// Get the IDs of nodes that must send their hash to this ID.
    pub fn dependencies_in(id: u64) -> Vec<u64> {
        let out = match id % 5 {
            0 => vec![-15i64, -5, -4, -1, 1],
            1 => vec![1, 3],
            2 => vec![1],
            3 => Vec::new(),
            4 => vec![-2, -1],
            _ => Vec::new(),
        };

        let out = out.iter()
            .map(|&v| {
                if v < 0 {
                    id.checked_sub(-v as u64)
                } else {
                    id.checked_add(v as u64)
                }
            })
            .flatten()
            .collect();
        out
    }

    /// The state of the node.
    pub fn state(&self) -> State {
        self.state
    }

    /// Take the content of the buffer into a new node.
    pub fn take(&mut self, new_state: State) -> BufferEntry {
        BufferEntry {
            id: self.id,
            payload: self.payload.take(),
            hashes: self.hashes.drain(..).collect(),
            signature: self.signature.take(),
            dependencies: self.dependencies.drain(..).collect(),
            state: new_state,
        }
    }

    /// Computes the hash of the packet with its children hashes.
    pub fn compute_total_hash(&self) -> [u8; 32] {
        // TODO.
        [0u8; 32]
    }

    /// Compare the children hashes with an external hash. Try to find a match.
    /// Currently iterates over all hashes.
    /// Returns an error if the current node is not itself authenticated.
    pub fn compare_hash(&self, hash: &[u8; 32]) -> Result<()> {
        if self.state != State::Authenticated {
            return Err(Error::NotAuthenticated);
        }

        for ok_hash in self.hashes.iter() {
            if ok_hash == hash {
                return Ok(());
            }
        }
        
        Err(Error::BadAuthentication)
    }
}

/// Buffer containing all hashes that need to be buffered.
/// Specific for the a=3,p=5 case.
pub struct Buffer {
    /// Data.
    /// The maximum number of hashes that must be buffered is p(a - 1) = 10.
    buffer: Vec<BufferEntry>,

    /// Lowest ID buffered.
    lowest_id: u64,

    /// Latests added ID in the buffer.
    latest_id: u64,

    /// Next node ID to process its hash forwarding.
    next_node_id_hash: u64,

    /// Whether the buffer waits for symbols to be ready (send buffer) or authenticated (receive buffer) to pop packets.
    state_to_pop: State,
}

impl Buffer {
    /// Creates a new, empty buffer.
    fn new(is_send: bool) -> Self {
        Self {
            buffer: (0..BUFF_SIZE)
                .map(|id| BufferEntry::new_id(id as u64))
                .collect(),
            lowest_id: 0,
            latest_id: 0,
            next_node_id_hash: 3,
            state_to_pop: if is_send { State::ReadySent } else { State::Authenticated },
        }
    }

    /// Returns the entry if it exists, or create it and returns a mutable reference to it.
    fn get_or_create(&mut self, id: u64) -> Result<&mut BufferEntry> {
        if id < self.lowest_id || id >= self.lowest_id + BUFF_SIZE as u64 {
            return Err(Error::OutOfBoundId);
        }

        let index = index!(id);
        let entry = &self.buffer[index];
        if entry.id != id {
            self.buffer[index] = BufferEntry::new_id(id);
        }
        
        Ok(&mut self.buffer[index])
    }

    /// Returns the next node ID to process to forward packet hashes.
    pub fn next_node_id_hash(&mut self) -> u64 {
        let id = self.next_node_id_hash;

        self.next_node_id_hash = match id % 5 {
            0 => id + 8,
            1 => id.saturating_sub(1),
            2 => id + 2,
            3 => id.saturating_sub(1),
            4 => id.saturating_sub(3),
            _ => id,
        };

        id
    }

    /// Pop ready symbols from the buffer in sequence.
    pub fn pop_ready_in_sequence(&mut self) -> Vec<BufferEntry> {
        let mut out = Vec::with_capacity(3);

        // Loop at most until we reach the end of the buffer size.
        for _ in 0..BUFF_SIZE {
            let index = index!(self.lowest_id);

            let entry = &mut self.buffer[index];
            if entry.id == self.lowest_id && entry.state == self.state_to_pop {
                out.push(entry.take(self.state_to_pop));
            } else {
                break;
            }

            self.lowest_id += 1;
        }

        out
    }
}

#[cfg(test)]
mod testing {
    use super::*;

    impl BufferEntry {
        pub fn dummy(id: u64) -> Self {
            let payload = vec![42u8; 100];
            Self::new(id, payload)
        }
    }
}

pub mod send_buf;
pub mod recv_buf;
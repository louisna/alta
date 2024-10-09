use std::collections::VecDeque;

use crate::Error;
use crate::Result;
use crate::ALTA_A;
use crate::ALTA_P;
use crate::{PktHash, Signature};

const BUFF_SIZE: usize = ALTA_A * ALTA_P + 1;

macro_rules! index {
    ($s:expr) => {
        $s as usize % BUFF_SIZE
    };
}

/// Internal representation of an element in the SendBuffer.
pub struct SendBufferEntry {
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

    /// Whether the node is ready to be sent on the wire.
    ready: bool,
}

impl SendBufferEntry {
    /// New simple entry with an ID.
    pub fn new_id(id: u64) -> Self {
        Self {
            hashes: VecDeque::with_capacity(5),
            signature: None,
            id,
            payload: None,
            dependencies: Self::dependencies_in(id),
            ready: false,
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
            0 => vec![-15i64, -5, -1, 1],
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

    /// Whether the node is ready to be sent on the wire.
    pub fn ready(&self) -> bool {
        self.ready
    }

    /// Take the content of the buffer into a new node.
    pub fn take(&mut self) -> SendBufferEntry {
        SendBufferEntry {
            id: self.id,
            payload: self.payload.take(),
            hashes: self.hashes.drain(..).collect(),
            signature: self.signature.take(),
            dependencies: self.dependencies.drain(..).collect(),
            ready: true,
        }
    }

    /// Computes the hash of the packet with its children hashes.
    pub fn compute_total_hash(&self) -> [u8; 32] {
        // TODO.
        [0u8; 32]
    }
}

/// Buffer containing all hashes that need to be buffered.
/// Specific for the a=3,p=5 case.
pub struct SendBuffer {
    /// Data.
    /// The maximum number of hashes that must be buffered is p(a - 1) = 10.
    buffer: Vec<SendBufferEntry>,

    /// Lowest ID buffered.
    lowest_id: u64,

    /// Latests added ID in the buffer.
    latest_id: u64,

    /// Next node ID to process its hash forwarding.
    next_node_id_hash: u64,
}

impl SendBuffer {
    /// Creates a new, empty buffer.
    pub fn new() -> Self {
        Self {
            buffer: (0..BUFF_SIZE)
                .map(|id| SendBufferEntry::new_id(id as u64))
                .collect(),
            lowest_id: 0,
            latest_id: 0,
            next_node_id_hash: 3,
        }
    }

    /// Inserts a new node in the graph.
    /// Calling this function assumes that the nodes are created in sequence.
    /// Returns an error otherwise.
    pub fn insert_in_sequence(&mut self, node: SendBufferEntry) -> Result<()> {
        if node.id < self.lowest_id || node.id >= self.lowest_id + BUFF_SIZE as u64 {
            return Err(Error::OutOfBoundId);
        }

        // Check whether we are trying to add a "too old" ID in the buffer, or a too recent.
        if node.id.saturating_sub(1) != self.latest_id {
            return Err(Error::IllegalInsert);
        }

        // Check if the node already exists.
        self.latest_id = node.id;
        let entry = self.get_or_create(node.id);
        entry.payload = node.payload;

        Ok(())
    }

    /// Returns the entry if it exists, or create it and returns a mutable reference to it.
    pub fn get_or_create(&mut self, id: u64) -> &mut SendBufferEntry {
        let index = index!(id);
        let entry = &self.buffer[index];
        if entry.id != id {
            self.buffer[index] = SendBufferEntry::new_id(id);
        }
        &mut self.buffer[index]
    }

    /// Forwards its packet hash to its output dependencies.
    /// This function assumes that in-hashes are added sequentially,
    /// i.e., if they need two hashes and there are indeed two hashes, it assumes that
    /// the two hashes correspond to the intended nodes.
    /// Returns an error `MissingHash` if this node does not have all the required hashes to proceed.
    pub fn forwards_hash(&mut self, id: u64) -> Result<()> {
        let idx = index!(id);
        let entry = &mut self.buffer[idx];

        // Already good for this node.
        if entry.ready {
            return Ok(());
        }

        if id != entry.id {
            return Err(Error::OutOfBoundId);
        }

        if entry.dependencies.len() != entry.hashes.len() {
            return Err(Error::MissingHash);
        }

        // TODO: compute the hash of the node based on all the received hashes etc.
        let hash = entry.compute_total_hash();

        // Node is now ready to be sent on the wire.
        entry.ready = true;

        // Send the hashes to all exiting nodes in the graph.
        let out_dep = entry.dependencies_out();
        for &next_node in out_dep.iter() {
            let node = self.get_or_create(next_node);
            node.hashes.push_back(hash);
        }

        Ok(())
    }

    /// Pop ready symbols from the buffer in sequence.
    pub fn pop_ready_in_sequence(&mut self) -> Vec<SendBufferEntry> {
        let mut out = Vec::with_capacity(3);

        // Loop at most until we reach the end of the buffer size.
        for _ in 0..BUFF_SIZE {
            let index = index!(self.lowest_id);

            let entry = &mut self.buffer[index];
            if entry.id == self.lowest_id && entry.ready {
                out.push(entry.take());
            }

            self.lowest_id += 1;
        }

        out
    }

    /// Returns the next node ID to process to forward packet hashes.
    pub fn next_node_id_hash(&mut self) -> u64 {
        let id = self.next_node_id_hash;

        self.next_node_id_hash = match id % 5 {
            0 => id + 5,
            1 => id.saturating_sub(1),
            2 => id + 2,
            3 => id.saturating_sub(1),
            4 => id.saturating_sub(3),
            _ => id,
        };

        id
    }
}

#[cfg(test)]
mod testing {
    use super::*;

    impl SendBufferEntry {
        pub fn dummy(id: u64) -> Self {
            let payload = vec![42u8; 100];
            Self::new(id, payload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_buffer() {
        let mut sb = SendBuffer::new();

        for id in 0..BUFF_SIZE {
            let entry = SendBufferEntry::dummy(id as u64);
            assert_eq!(sb.insert_in_sequence(entry), Ok(()));
        }

        // Buffer is full.
        let entry = SendBufferEntry::dummy(BUFF_SIZE as u64);
        assert_eq!(sb.insert_in_sequence(entry), Err(Error::OutOfBoundId));

        // Computing the hash of packets is only possible for the node index 3.
        for id in 0..6 {
            if id == 3 {
                continue;
            }

            assert_eq!(sb.forwards_hash(id as u64), Err(Error::MissingHash));
        }

        assert_eq!(sb.next_node_id_hash(), 3);
        assert_eq!(sb.forwards_hash(3), Ok(()));
        let entry = &sb.buffer[3];
        assert_eq!(entry.id, 3);
        assert!(entry.ready);
        assert_eq!(sb.next_node_id_hash(), 2);
        assert_eq!(sb.forwards_hash(2), Ok(()));

        // TODO: continue distributing the hashes.
    }
}

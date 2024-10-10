use super::Buffer;
use super::BufferEntry;
use super::State;
use super::BUFF_SIZE;
use crate::Error;
use crate::Result;

/// SendBuffer-specific methods.
pub trait SendBuffer {
    /// Creates a new receive buffer.
    fn new() -> Self;

    /// Inserts a new node in the graph.
    /// Calling this function assumes that the nodes are created in sequence.
    /// Returns an error otherwise.
    fn insert_in_sequence(&mut self, node: BufferEntry) -> Result<()>;

    /// Forwards its packet hash to its output dependencies.
    /// This function assumes that in-hashes are added sequentially,
    /// i.e., if they need two hashes and there are indeed two hashes, it assumes that
    /// the two hashes correspond to the intended nodes.
    /// Returns an error `MissingHash` if this node does not have all the required hashes to proceed.
    fn forwards_hash(&mut self, id: u64) -> Result<()>;
}

impl SendBuffer for Buffer {
    fn new() -> Self {
        Buffer::new(true)
    }

    fn insert_in_sequence(&mut self, node: BufferEntry) -> Result<()> {
        if node.id < self.lowest_id || node.id >= self.lowest_id + BUFF_SIZE as u64 {
            return Err(Error::OutOfBoundId);
        }

        // Check whether we are trying to add a "too old" ID in the buffer, or a too recent.
        if node.id.saturating_sub(1) != self.latest_id {
            return Err(Error::IllegalInsert);
        }

        // Check if the node already exists.
        self.latest_id = node.id;
        let entry = self.get_or_create(node.id)?;
        entry.payload = node.payload;

        Ok(())
    }

    /// Forwards its packet hash to its output dependencies.
    /// This function assumes that in-hashes are added sequentially,
    /// i.e., if they need two hashes and there are indeed two hashes, it assumes that
    /// the two hashes correspond to the intended nodes.
    /// Returns an error `MissingHash` if this node does not have all the required hashes to proceed.
    fn forwards_hash(&mut self, id: u64) -> Result<()> {
        let idx = index!(id);
        let entry_opt = self.buffer[idx].as_mut();

        if let Some(entry) = entry_opt {
            // Already good for this node.
            if entry.state == State::ReadySent {
                return Ok(());
            }
    
            if id != entry.id {
                return Err(Error::OutOfBoundId);
            }
    
            if entry.dependencies.len() != entry.hashes.len() {
                return Err(Error::MissingHash);
            }
    
            // Ensure that we can push this node only if we can already propagate its hashes.
            if entry
                .dependencies_out()
                .iter()
                .max()
                .map(|&m| m >= self.lowest_id + BUFF_SIZE as u64)
                .unwrap_or(false)
            {
                return Err(Error::OutOfBoundId);
            }
    
            // TODO: compute the hash of the node based on all the received hashes etc.
            let hash = entry.compute_total_hash();
    
            // Node is now ready to be sent on the wire.
            entry.state = State::ReadySent;
    
            // Send the hashes to all exiting nodes in the graph.
            let out_dep = entry.dependencies_out();
            for &next_node in out_dep.iter() {
                let node = self.get_or_create(next_node)?;
                node.hashes.push_back(hash);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod testing {
    use super::*;

    impl Buffer {
        /// Push as many packets as possible in the buffer.
        /// Returns the next ID.
        pub fn push_pkts(&mut self, start_id: u64) -> u64 {
            let mut id = start_id;
            loop {
                let entry = BufferEntry::dummy(id);
                if let Err(_) = self.insert_in_sequence(entry) {
                    break;
                }
                id += 1;
            }
            id
        }

        /// Forward as many hashes as possible.
        /// Iterate over all elements of the buffer.
        pub fn forw_hash(&mut self) {
            for i in 0..BUFF_SIZE {
                let _ = self.forwards_hash(self.lowest_id + i as u64);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_buffer() {
        let mut sb: Buffer = SendBuffer::new();

        for id in 0..BUFF_SIZE {
            let entry = BufferEntry::dummy(id as u64);
            assert_eq!(sb.insert_in_sequence(entry), Ok(()));
        }

        // Buffer is full.
        let entry = BufferEntry::dummy(BUFF_SIZE as u64);
        assert_eq!(sb.insert_in_sequence(entry), Err(Error::OutOfBoundId));

        // Computing the hash of packets is only possible for the node index 3.
        for id in 0..6 {
            if id == 3 {
                continue;
            }

            assert_eq!(sb.forwards_hash(id as u64), Err(Error::MissingHash));
        }

        for _ in 0..9 {
            let id = sb.next_node_id_hash();
            if id as usize > BUFF_SIZE {
                break;
            }
            assert_eq!(sb.forwards_hash(id), Ok(()));
            let entry = sb.buffer[id as usize].as_ref().unwrap();
            assert_eq!(entry.id, id);
            assert_eq!(entry.state, State::ReadySent);
        }

        // Now all packets should be able to be sent on the wire.
        let out = sb.pop_ready_in_sequence();
        assert_eq!(out.len(), 5);
        assert_eq!(sb.lowest_id, 5);
    }
}

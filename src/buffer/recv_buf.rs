use super::Buffer;
use super::BufferEntry;
use crate::Result;
use crate::Error;
use super::BUFF_SIZE;
use super::State;

pub trait RecvBuf {
    /// Creates a new receive buffer.
    fn new() -> Self;

    /// Inserts a node in the buffer.
    /// Returns an error if the node exceeds the capacity of the buffer.
    fn insert(&mut self, node: BufferEntry) -> Result<()>;

    /// Tries to authenticate the node, either using the (optional) digital signature,
    /// or using a parent node that has already been authenticated.
    /// If the current node has been authenticated, recursively calls the function on children nodes.
    fn authenticate_node(&mut self, id: u64) -> Result<()>;
}

impl RecvBuf for Buffer {
    fn new() -> Self {
        Buffer::new(false)
    }

    fn insert(&mut self, mut node: BufferEntry) -> Result<()> {
        let id = node.id;
        let idx = index!(id);
        
        if id < self.lowest_id || id >= self.lowest_id + BUFF_SIZE as u64 {
            return Err(Error::OutOfBoundId);
        }

        // Check whether the node is already present in the buffer.
        let entry = self.buffer[idx].as_mut();
        if entry.is_some_and(|e| e.id == id) {
            return Ok(());
        }

        // Just be sure that the node is not ready yet.
        node.state = State::NotReady;
        // Insert the node.
        self.buffer[index!(idx)] = Some(node);

        // Try to authenticate the node either using the (optional) digital signature,
        // or if a parent node has hashes.
        self.authenticate_node(id)?;

        Ok(())
    }

    fn authenticate_node(&mut self, id: u64) -> Result<()> {
        let entry_opt = self.buffer[index!(id)].as_mut();
        if let Some(entry) = entry_opt {
            if entry.id != id {
                return Ok(());
            }
    
            if entry.state == State::Authenticated {
                // Assumes that children nodes have been processed already in this context.
                return Ok(());
            }
    
            // Authenticate the node if it contains a digital signature.
            // Otherwise, try to call an authenticated parent to authenticate this node.
            if let Some(_sign) = entry.signature.as_ref() {
                // TODO.
                // For now assumes that it is always true.
                entry.state = State::Authenticated;
            } else {
                // Compute the hash of this node to verify the match with the parent.
                let node_hash = entry.compute_total_hash();
    
                // Iterate over its parents, hopefully find an authenticated node to authenticate this one.
                for parent_id in entry.dependencies_out() {
                    let parent_opt = self.buffer[index!(parent_id)].as_ref();

                    if let Some(parent) = parent_opt {
                        // Cannot use this parent because it is not already here or it is not authenticated.
                        if parent.id != parent_id || parent.state != State::Authenticated {
                            continue;
                        }
        
                        // The parent is authenticated (yeay!) so we can match the hash to authenticate this one.
                        match parent.compare_hash(&node_hash) {
                            Ok(()) => {
                                self.buffer[index!(id)].as_mut().unwrap().state = State::Authenticated;
                                break;
                            },
                            Err(Error::NotAuthenticated) => continue,
                            Err(e) => return Err(e),
                        }
                    }
                    
                }
            }
    
            let entry = self.buffer[index!(id)].as_mut().unwrap();
            match entry.state {
                // Recursively call children if the current node has been identified.
                State::Authenticated => {
                    for children in entry.dependencies.clone() {
                        self.authenticate_node(children)?;
                    }
                },
    
                State::BadAuthentication => return Err(Error::BadAuthentication),
    
                _ => (),
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recv_buffer() {
        // First create a sequence of authenticated packets.
        let mut sb = Buffer::new(true);

        let mut nodes = Vec::new();
        let mut id = 0;
        while nodes.len() < 60 {
            // Push as much packets as possible.
            id = sb.push_pkts(id);

            // Forward the hashes.
            sb.forw_hash();

            // Get all ready packets.
            nodes.extend(sb.pop_ready_in_sequence());
        }

        // TODO: add some signatures to the nodes.
        // We will add to each five node.
        for i in 1..12 {
            nodes[5 * i].signature = Some([1; 64]);
        }
        nodes.last_mut().map(|n| n.signature = Some([1; 64]));

        // Now that we got all authenticated nodes, we will add it to the receive buffer.
        let mut rb = Buffer::new(false);

        let mut authenticated_nodes = Vec::new();

        for node in nodes.drain(..) {
                // Push as many nodes as possible.
                if let Err(_) = rb.insert(node) {
                    assert!(false);
                }

                // Authenticate as many nodes as possible.
                for i in 0..BUFF_SIZE {
                    let _ = rb.authenticate_node(i as u64 + rb.lowest_id);
                }

                // Get as many nodes as possible.
                authenticated_nodes.extend(rb.pop_ready_in_sequence());
            }

        assert_eq!(authenticated_nodes.len(), 56);
        for node in authenticated_nodes.iter() {
            assert_eq!(node.state, State::Authenticated);
        }
    }
}
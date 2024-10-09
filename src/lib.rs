pub type PktHash = [u8; 32];
pub type Signature = [u8; 64];

const ALTA_A: usize = 3;
const ALTA_P: usize = 5;

pub mod node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The node has an ID out of bounds.
    OutOfBoundId,

    /// The current node misses some packet hashes and cannot be processed.
    MissingHash,

    /// Trying to insert an illegal node in the graph.
    IllegalInsert,
}

pub type Result<T> = std::result::Result<T, Error>;
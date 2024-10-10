pub type PktHash = [u8; 32];
pub type Signature = [u8; 64];

const ALTA_A: usize = 3;
const ALTA_P: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The node has an ID out of bounds.
    OutOfBoundId,

    /// The current node misses some packet hashes and cannot be processed.
    MissingHash,

    /// Trying to insert an illegal node in the graph.
    IllegalInsert,

    /// The reception buffer is full and the node cannot be added.
    /// This happens whether the the caller attemps to add a node in the graph,
    /// and propagating the node's hash to succeding nodes mught erase existing symbols.
    BufferFull,

    /// Wrong authentication, the node was uncorrectly authenticated.
    BadAuthentication,

    /// The current node cannot authenticate a children's node.
    /// This happens whether the node is not itself authenticated.
    NotAuthenticated,

    /// Decoding error.
    Decoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Node is buffered but not processed yet.
    NotReady,

    /// Ready to be sent on the wire.
    ReadySent,

    /// Authenticated Node.
    Authenticated,

    /// Bad authentication.
    BadAuthentication,
}

pub type Result<T> = std::result::Result<T, Error>;

pub mod buffer;
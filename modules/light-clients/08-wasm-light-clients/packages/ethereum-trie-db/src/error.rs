#[derive(Debug, PartialEq, thiserror::Error, Clone)]
pub enum TrieDBError {
    #[error("get trie node failed: {0}")]
    GetTrieNodeFailed(String),

    #[error("rlp decoding failed: {0:?}")]
    RlpDecode(#[from] rlp::DecoderError),

    #[error(
        "proof is invalid due to value mismatch, expected: {expected}, actual: {actual}",
        expected = utils::hex::to_hex(expected),
        actual = utils::hex::to_hex(actual)
    )]
    ValueMismatch { expected: Vec<u8>, actual: Vec<u8> },

    #[error("proof is invalid due to missing value: {v}", v = utils::hex::to_hex(value))]
    ValueMissing { value: Vec<u8> },
}

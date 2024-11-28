#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum EthereumIBCError {
    #[error("IBC path is empty")]
    EmptyPath,

    #[error("unable to decode storage proof")]
    StorageProofDecode,

    #[error("invalid commitment key, expected ({0}) but found ({1})")]
    InvalidCommitmentKey(String, String),

    #[error("expected value ({0}) and stored value ({1}) don't match")]
    StoredValueMistmatch(String, String),

    #[error("verify storage proof error: {0}")]
    VerifyStorageProof(String),
}

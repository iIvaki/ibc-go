use alloy_primitives::B256;

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

    #[error("insufficient number of sync committee participants ({0})")]
    InsufficientSyncCommitteeParticipants(usize),

    #[error("update header contains deneb specific information")]
    MustBeDeneb,

    #[error("invalid chain version")]
    InvalidChainVersion,

    #[error(transparent)]
    InvalidMerkleBranch(#[from] InvalidMerkleBranch),
}

#[derive(Debug, PartialEq, Clone, thiserror::Error)]
#[error("invalid merkle branch \
    (leaf: {leaf}, branch: [{branch}], \
    depth: {depth}, index: {index}, root: {root})",
    branch = .branch.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
)]
pub struct InvalidMerkleBranch {
    pub leaf: B256,
    pub branch: Vec<B256>,
    pub depth: usize,
    pub index: u64,
    pub root: B256,
}

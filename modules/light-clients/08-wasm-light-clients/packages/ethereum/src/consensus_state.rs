use alloy_primitives::{FixedBytes, B256};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConsensusState {
    pub slot: u64,
    /// The state root for this chain, used for L2s to verify against this contract.
    pub state_root: B256,
    pub storage_root: B256,
    /// Timestamp of the block, *normalized to nanoseconds* in order to be compatible with ibc-go.
    pub timestamp: u64,
    /// aggregate public key of current sync committee
    pub current_sync_committee: FixedBytes<48>,
    /// aggregate public key of next sync committee
    pub next_sync_committee: Option<FixedBytes<48>>,
}

impl From<Vec<u8>> for ConsensusState {
    fn from(value: Vec<u8>) -> Self {
        serde_json::from_slice(&value).unwrap()
    }
}

impl From<ConsensusState> for Vec<u8> {
    fn from(value: ConsensusState) -> Self {
        serde_json::to_vec(&value).unwrap()
    }
}

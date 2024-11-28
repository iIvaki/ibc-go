use alloy_primitives::{aliases::B32, Address, B256, U256};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ClientState {
    pub chain_id: u64,
    pub genesis_validators_root: B256,
    pub min_sync_committee_participants: u64,
    pub genesis_time: u64,
    pub fork_parameters: ForkParameters,
    pub seconds_per_slot: u64,
    pub slots_per_epoch: u64,
    pub epochs_per_sync_committee_period: u64,
    pub latest_slot: u64,
    // TODO: Should this be frozen_slot?
    // pub frozen_height: Height,
    pub ibc_commitment_slot: U256,
    pub ibc_contract_address: Address,
}

impl From<Vec<u8>> for ClientState {
    fn from(value: Vec<u8>) -> Self {
        serde_json::from_slice(&value).unwrap()
    }
}

impl From<ClientState> for Vec<u8> {
    fn from(value: ClientState) -> Self {
        serde_json::to_vec(&value).unwrap()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ForkParameters {
    pub genesis_fork_version: B32,
    pub genesis_slot: u64,
    pub altair: Fork,
    pub bellatrix: Fork,
    pub capella: Fork,
    pub deneb: Fork,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Fork {
    pub version: B32,
    pub epoch: u64,
}

use alloy_primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Serialize};
use tree_hash_derive::TreeHash;

use crate::config::consts::{floorlog2, FINALIZED_ROOT_INDEX, NEXT_SYNC_COMMITTEE_INDEX};

use super::{
    bls::BlsSignature,
    sync_committee::{SyncCommittee, TrustedSyncCommittee},
    wrappers::{MyBloom, MyBytes, MyExecutionPayloadBranch},
};

pub type NextSyncCommitteeBranch = [B256; floorlog2(NEXT_SYNC_COMMITTEE_INDEX)];
pub type FinalityBranch = [B256; floorlog2(FINALIZED_ROOT_INDEX)];

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct Header {
    pub trusted_sync_committee: TrustedSyncCommittee,
    pub consensus_update: LightClientUpdate,
    pub account_update: AccountUpdate,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct LightClientUpdate {
    /// Header attested to by the sync committee
    pub attested_header: LightClientHeader,
    /// Next sync committee corresponding to `attested_header.state_root`
    // NOTE: These fields aren't actually optional, they are just because of the current structure of the ethereum Header.
    // TODO: Remove the Option and improve ethereum::header::Header to be an enum, instead of using optional fields and bools.
    #[serde(default)]
    pub next_sync_committee: Option<SyncCommittee>,
    #[serde(default)]
    pub next_sync_committee_branch: Option<NextSyncCommitteeBranch>,
    /// Finalized header corresponding to `attested_header.state_root`
    pub finalized_header: LightClientHeader,
    pub finality_branch: FinalityBranch,
    /// Sync committee aggregate signature
    pub sync_aggregate: SyncAggregate,
    /// Slot at which the aggregate signature was created (untrusted)
    pub signature_slot: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct AccountUpdate {
    pub account_proof: AccountProof,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct AccountProof {
    pub storage_root: B256,
    pub proof: Vec<Bytes>,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default, TreeHash)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeader,
    pub execution_branch: MyExecutionPayloadBranch,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default, TreeHash)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct SyncAggregate {
    /// The bits representing the sync committee's participation.
    pub sync_committee_bits: Bytes,
    /// The aggregated signature of the sync committee.
    pub sync_committee_signature: BlsSignature,
}

impl SyncAggregate {
    // TODO: Unit test
    /// Returns the number of bits that are set to `true`.
    #[must_use]
    pub fn num_sync_committe_participants(&self) -> usize {
        self.sync_committee_bits
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default, TreeHash)]
pub struct ExecutionPayloadHeader {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: MyBloom,
    pub prev_randao: B256,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: MyBytes,
    pub base_fee_per_gas: U256,
    pub block_hash: B256,
    pub transactions_root: B256,
    pub withdrawals_root: B256,
    // new in Deneb
    pub blob_gas_used: u64,
    // new in Deneb
    pub excess_blob_gas: u64,
}

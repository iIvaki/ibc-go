use alloy_primitives::Bytes;
use serde::{Deserialize, Serialize};
use tree_hash_derive::TreeHash;
use utils::slot::compute_epoch_at_slot;

use super::{
    bls::{BlsPublicKey, BlsSignature},
    height::Height,
    wrappers::VecBlsPublicKey,
};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default, TreeHash)]
pub struct SyncCommittee {
    pub pubkeys: VecBlsPublicKey,
    pub aggregate_pubkey: BlsPublicKey,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum ActiveSyncCommittee {
    Current(SyncCommittee),
    Next(SyncCommittee),
}

impl Default for ActiveSyncCommittee {
    fn default() -> Self {
        ActiveSyncCommittee::Current(SyncCommittee {
            pubkeys: VecBlsPublicKey::default(),
            aggregate_pubkey: BlsPublicKey::default(),
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct TrustedSyncCommittee {
    pub trusted_height: Height,
    pub sync_committee: ActiveSyncCommittee,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct SyncAggregate {
    /// The bits representing the sync committee's participation.
    pub sync_committee_bits: Bytes, // TODO: Consider changing this to a BitVector
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

    // TODO: Unit test
    // Returns if at least 2/3 of the sync committee signed
    //
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#process_light_client_update
    pub fn validate_signature_supermajority(&self) -> bool {
        self.num_sync_committe_participants() * 3 >= self.sync_committee_bits.len() * 2
    }
}

/// Returns the sync committee period at a given `epoch`.
///
/// [See in consensus-spec](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/validator.md#sync-committee)
pub fn compute_sync_committee_period(epochs_per_sync_committee_period: u64, epoch: u64) -> u64 {
    epoch / epochs_per_sync_committee_period
}

/// Returns the sync committee period at a given `slot`.
///
/// [See in consensus-spec](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#compute_sync_committee_period_at_slot)
pub fn compute_sync_committee_period_at_slot(
    slots_per_epoch: u64,
    epochs_per_sync_committee_period: u64,
    slot: u64,
) -> u64 {
    compute_sync_committee_period(
        epochs_per_sync_committee_period,
        compute_epoch_at_slot(slots_per_epoch, slot),
    )
}

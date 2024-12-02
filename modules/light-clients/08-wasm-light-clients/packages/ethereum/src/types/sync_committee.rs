use serde::{Deserialize, Serialize};
use tree_hash_derive::TreeHash;

use super::{bls::BlsPublicKey, height::Height, wrappers::VecBlsPublicKey};

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

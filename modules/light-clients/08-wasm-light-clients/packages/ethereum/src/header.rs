use alloy_primitives::{Address, Bloom, Bytes, B256, U256};
use alloy_rpc_types_beacon::BlsPublicKey;

use serde::{Deserialize, Serialize};
use tree_hash::{MerkleHasher, TreeHash, BYTES_PER_CHUNK};
use tree_hash_derive::TreeHash;

use crate::{
    client_state::{ClientState, ForkParameters},
    config::consts::{
        floorlog2, EXECUTION_PAYLOAD_INDEX, FINALIZED_ROOT_INDEX, NEXT_SYNC_COMMITTEE_INDEX,
    },
    consensus_state::ConsensusState,
    error::EthereumIBCError,
    extras::utils::ensure,
};

pub const GENESIS_SLOT: u64 = 0;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct Header {
    pub trusted_sync_committee: TrustedSyncCommittee,
    pub consensus_update: LightClientUpdate,
    pub account_update: AccountUpdate,
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

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct TrustedSyncCommittee {
    pub trusted_height: Height,
    pub sync_committee: ActiveSyncCommittee,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct Height {
    #[serde(default)]
    pub revision_number: u64,
    pub revision_height: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum ActiveSyncCommittee {
    Current(SyncCommittee),
    Next(SyncCommittee),
}

impl Default for ActiveSyncCommittee {
    fn default() -> Self {
        ActiveSyncCommittee::Current(SyncCommittee {
            pubkeys: Vec::default(),
            aggregate_pubkey: BlsPublicKey::default(),
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct SyncCommittee {
    //#[serde(with = "::serde_utils::hex_string_list")]
    pub pubkeys: Vec<BlsPublicKey>,
    //#[serde(with = "::serde_utils::hex_string")]
    pub aggregate_pubkey: BlsPublicKey,
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
    //#[serde(with = "::serde_utils::string")]
    pub signature_slot: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct SyncAggregate {
    /// The bits representing the sync committee's participation.
    pub sync_committee_bits: Bytes,
    /// The aggregated signature of the sync committee.
    pub sync_committee_signature: Bytes,
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

pub type NextSyncCommitteeBranch = [B256; floorlog2(NEXT_SYNC_COMMITTEE_INDEX)];
pub type FinalityBranch = [B256; floorlog2(FINALIZED_ROOT_INDEX)];

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default, TreeHash)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeader,
    pub execution_branch: MyExecutionPayloadBranch,
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct MyExecutionPayloadBranch(pub [B256; floorlog2(EXECUTION_PAYLOAD_INDEX)]);

impl TreeHash for MyExecutionPayloadBranch {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let mut hasher = MerkleHasher::with_leaves(floorlog2(EXECUTION_PAYLOAD_INDEX));

        for item in &self.0 {
            hasher.write(item.tree_hash_root()[..1].as_ref()).unwrap()
        }

        let res = hasher.finish().unwrap();
        res
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default, TreeHash)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

#[derive(
    Serialize,
    Deserialize,
    PartialEq,
    Clone,
    Debug,
    Default,
    //ssz_derive::Decode,
    //ssz_derive::Encode,
    TreeHash,
)]
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

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct MyBytes(pub Bytes);

impl TreeHash for MyBytes {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let leaves = (self.0.len() + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK;

        let mut hasher = MerkleHasher::with_leaves(leaves);

        for item in &self.0 {
            hasher.write(item.tree_hash_root()[..1].as_ref()).unwrap()
        }

        tree_hash::mix_in_length(&hasher.finish().unwrap(), self.0.len())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct MyBloom(pub Bloom);
impl TreeHash for MyBloom {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let leaves = (self.0.len() + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK;

        let mut hasher = MerkleHasher::with_leaves(leaves);

        for item in &self.0 {
            hasher.write(item.tree_hash_root()[..1].as_ref()).unwrap()
        }

        let res = hasher.finish().unwrap();
        res
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct TrustedConsensusState {
    pub state: ConsensusState,
    /// Full sync committee data which corresponds to the aggregate key that we
    /// store at the client.
    ///
    /// This sync committee can either be the current sync committee or the next sync
    /// committee. That's because the verifier uses next or current sync committee's
    /// public keys to verify the signature against. It is based on
    pub sync_committee: ActiveSyncCommittee,
}

pub fn verify_header(
    consensus_state: ConsensusState,
    client_state: ClientState,
    current_timestamp: u64,
    header: Header,
) -> Result<(), EthereumIBCError> {
    let trusted_sync_committee = header.trusted_sync_committee;
    let _trusted_consensus_state = TrustedConsensusState {
        state: consensus_state,
        sync_committee: trusted_sync_committee.sync_committee,
    };
    //let ctx = LightClientContext::new(&wasm_client_state.data, trusted_consensus_state);
    //
    // Ethereum consensus-spec says that we should use the slot at the current timestamp.
    let _current_slot = compute_slot_at_timestamp(
        client_state.genesis_time,
        client_state.seconds_per_slot,
        current_timestamp,
    )
    .unwrap();

    //validate_light_client_update(
    //    &ctx,
    //    header.consensus_update.clone(),
    //    current_slot,
    //    client_state.genesis_validators_root,
    //)
    //.map_err(Error::ValidateLightClient)?;
    //
    //// check whether at least 2/3 of the sync committee signed
    //ensure(
    //    validate_signature_supermajority::<Config>(
    //        &header.consensus_update.sync_aggregate.sync_committee_bits,
    //    ),
    //    Error::NotEnoughSignatures,
    //)?;
    //
    //let proof_data = header.account_update.account_proof;
    //
    //verify_account_storage_root(
    //    header.consensus_update.attested_header.execution.state_root,
    //    &wasm_client_state.data.ibc_contract_address,
    //    &proof_data.proof,
    //    &proof_data.storage_root,
    //)
    //.map_err(|err| {
    //    Error::TestVerifyStorageProof(
    //        err,
    //        to_hex(
    //            &header
    //                .consensus_update
    //                .attested_header
    //                .execution
    //                .state_root
    //                .into_bytes(),
    //        ),
    //        to_hex(&wasm_client_state.data.ibc_contract_address.into_bytes()),
    //        to_hex(&proof_data.proof.first().unwrap()),
    //        to_hex(&proof_data.storage_root.into_bytes()),
    //    )
    //});

    Ok(())
}

pub fn compute_slot_at_timestamp(
    genesis_time: u64,
    seconds_per_slot: u64,
    timestamp_seconds: u64,
) -> Option<u64> {
    timestamp_seconds
        .checked_sub(genesis_time)?
        .checked_div(seconds_per_slot)?
        .checked_add(GENESIS_SLOT)
}

/// Verifies if the light client `update` is valid.
///
/// * `update`: The light client update we want to verify.
/// * `current_slot`: The slot number computed based on the current timestamp.
/// * `genesis_validators_root`: The latest `genesis_validators_root` that is saved by the light client.
/// * `bls_verifier`: BLS verification implementation.
///
/// ## Important Notes
/// * This verification does not assume that the updated header is greater (in terms of height) than the
///   light client state. When the updated header is in the next signature period, the light client uses
///   the next sync committee to verify the signature, then it saves the next sync committee as the current
///   sync committee. However, it's not mandatory for light clients to expect the next sync committee to be given
///   during these updates. So if it's not given, the light client still can validate updates until the next signature
///   period arrives. In a situation like this, the update can be any header within the same signature period. And
///   this function only allows a non-existent next sync committee to be set in that case. It doesn't allow a sync committee
///   to be changed or removed.
///
/// [See in consensus-spec](https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md#validate_light_client_update)
pub fn validate_light_client_update(
    _client_state: ClientState,
    _update: LightClientUpdate,
    _current_slot: u64,
    _genesis_validators_root: B256,
) -> Result<(), EthereumIBCError> {
    //// Verify sync committee has sufficient participants
    //let sync_aggregate = &update.sync_aggregate;
    //
    //ensure(
    //    sync_aggregate.num_sync_committe_participants()
    //        >= client_state
    //            .min_sync_committee_participants
    //            .try_into()
    //            .unwrap(),
    //    EthereumIBCError::InsufficientSyncCommitteeParticipants(
    //        sync_aggregate.num_sync_committe_participants(),
    //    ),
    //)?;
    //
    //is_valid_light_client_header(ctx.fork_parameters(), &update.attested_header)?;
    //
    //// Verify update does not skip a sync committee period
    //let update_attested_slot = update.attested_header.beacon.slot;
    //let update_finalized_slot = update.finalized_header.beacon.slot;
    //
    //ensure(
    //    update_finalized_slot != GENESIS_SLOT,
    //    Error::FinalizedSlotIsGenesis,
    //)?;
    //
    //ensure(
    //    current_slot >= update.signature_slot,
    //    Error::UpdateMoreRecentThanCurrentSlot {
    //        current_slot,
    //        update_signature_slot: update.signature_slot,
    //    },
    //)?;
    //
    //ensure(
    //    update.signature_slot > update_attested_slot
    //        && update_attested_slot >= update_finalized_slot,
    //    Error::InvalidSlots {
    //        update_signature_slot: update.signature_slot,
    //        update_attested_slot,
    //        update_finalized_slot,
    //    },
    //)?;
    //
    //// Let's say N is the signature period of the header we store, we can only do updates with
    //// the following settings:
    //// 1. stored_period = N, signature_period = N:
    ////     - the light client must have the `current_sync_committee` and use it to verify the new header.
    //// 2. stored_period = N, signature_period = N + 1:
    ////     - the light client must have the `next_sync_committee` and use it to verify the new header.
    //let stored_period =
    //    compute_sync_committee_period_at_slot::<Ctx::ChainSpec>(ctx.finalized_slot());
    //let signature_period =
    //    compute_sync_committee_period_at_slot::<Ctx::ChainSpec>(update.signature_slot);
    //
    //if ctx.next_sync_committee().is_some() {
    //    ensure(
    //        signature_period == stored_period || signature_period == stored_period + 1,
    //        Error::InvalidSignaturePeriodWhenNextSyncCommitteeExists {
    //            signature_period,
    //            stored_period,
    //        },
    //    )?;
    //} else {
    //    ensure(
    //        signature_period == stored_period,
    //        Error::InvalidSignaturePeriodWhenNextSyncCommitteeDoesNotExist {
    //            signature_period,
    //            stored_period,
    //        },
    //    )?;
    //}
    //
    //// Verify update is relevant
    //let update_attested_period =
    //    compute_sync_committee_period_at_slot::<Ctx::ChainSpec>(update_attested_slot);
    //
    //// There are two options to do a light client update:
    //// 1. We are updating the header with a newer one.
    //// 2. We haven't set the next sync committee yet and we can use any attested header within the same
    //// signature period to set the next sync committee. This means that the stored header could be larger.
    //// The light client implementation needs to take care of it.
    //ensure(
    //    update_attested_slot > ctx.finalized_slot()
    //        || (update_attested_period == stored_period
    //            && update.next_sync_committee.is_some()
    //            && ctx.next_sync_committee().is_none()),
    //    Error::IrrelevantUpdate {
    //        update_attested_slot,
    //        trusted_finalized_slot: ctx.finalized_slot(),
    //        update_attested_period,
    //        stored_period,
    //        update_sync_committee_is_set: update.next_sync_committee.is_some(),
    //        trusted_next_sync_committee_is_set: ctx.next_sync_committee().is_some(),
    //    },
    //)?;
    //
    //// Verify that the `finality_branch`, if present, confirms `finalized_header`
    //// to match the finalized checkpoint root saved in the state of `attested_header`.
    //// NOTE(aeryz): We always expect to get `finalized_header` and it's embedded into the type definition.
    //is_valid_light_client_header(ctx.fork_parameters(), &update.finalized_header)?;
    //let finalized_root = update.finalized_header.beacon.tree_hash_root();
    //
    //// This confirms that the `finalized_header` is really finalized.
    //validate_merkle_branch(
    //    &finalized_root.into(),
    //    &update.finality_branch,
    //    floorlog2(FINALIZED_ROOT_INDEX),
    //    get_subtree_index(FINALIZED_ROOT_INDEX),
    //    &update.attested_header.beacon.state_root,
    //)?;
    //
    //// Verify that if the update contains the next sync committee, and the signature periods do match,
    //// next sync committees match too.
    //if let (Some(next_sync_committee), Some(stored_next_sync_committee)) =
    //    (&update.next_sync_committee, ctx.next_sync_committee())
    //{
    //    if update_attested_period == stored_period {
    //        ensure(
    //            next_sync_committee == stored_next_sync_committee,
    //            Error::NextSyncCommitteeMismatch {
    //                expected: stored_next_sync_committee.aggregate_pubkey,
    //                found: next_sync_committee.aggregate_pubkey,
    //            },
    //        )?;
    //    }
    //    // This validates the given next sync committee against the attested header's state root.
    //    validate_merkle_branch(
    //        &next_sync_committee.tree_hash_root().into(),
    //        &update.next_sync_committee_branch.unwrap_or_default(),
    //        floorlog2(NEXT_SYNC_COMMITTEE_INDEX),
    //        get_subtree_index(NEXT_SYNC_COMMITTEE_INDEX),
    //        &update.attested_header.beacon.state_root,
    //    )?;
    //}
    //
    //// Verify sync committee aggregate signature
    //let sync_committee = if signature_period == stored_period {
    //    ctx.current_sync_committee()
    //        .ok_or(Error::ExpectedCurrentSyncCommittee)?
    //} else {
    //    ctx.next_sync_committee()
    //        .ok_or(Error::ExpectedNextSyncCommittee)?
    //};
    //
    //// It's not mandatory for all of the members of the sync committee to participate. So we are extracting the
    //// public keys of the ones who participated.
    //let participant_pubkeys = update
    //    .sync_aggregate
    //    .sync_committee_bits
    //    .iter()
    //    .zip(sync_committee.pubkeys.iter())
    //    .filter_map(|(included, pubkey)| included.then_some(pubkey))
    //    .collect::<Vec<_>>();
    //
    //let fork_version_slot = std::cmp::max(update.signature_slot, 1) - 1;
    //let fork_version = compute_fork_version(
    //    ctx.fork_parameters(),
    //    compute_epoch_at_slot::<Ctx::ChainSpec>(fork_version_slot),
    //);
    //
    //let domain = compute_domain(
    //    DomainType::SYNC_COMMITTEE,
    //    Some(fork_version),
    //    Some(genesis_validators_root),
    //    ctx.fork_parameters().genesis_fork_version,
    //);
    //let signing_root = compute_signing_root(&update.attested_header.beacon, domain);
    //
    //bls_verifier.fast_aggregate_verify(
    //    participant_pubkeys,
    //    signing_root.as_ref().to_owned(),
    //    sync_aggregate.sync_committee_signature,
    //)?;
    //
    Ok(())
}

/// Validates a light client header.
///
/// [See in consensus-spec](https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/light-client/sync-protocol.md#modified-is_valid_light_client_header)
pub fn is_valid_light_client_header(
    client_state: ClientState,
    fork_parameters: ForkParameters,
    header: LightClientHeader,
) -> Result<(), EthereumIBCError> {
    let epoch = compute_epoch_at_slot(client_state.slots_per_epoch, header.beacon.slot);

    if epoch < fork_parameters.deneb.epoch {
        ensure(
            header.execution.blob_gas_used == 0 && header.execution.excess_blob_gas == 0,
            EthereumIBCError::MustBeDeneb,
        )?;
    }

    ensure(
        epoch >= fork_parameters.capella.epoch,
        EthereumIBCError::InvalidChainVersion,
    )?;

    //validate_merkle_branch(
    //    &get_lc_execution_root(fork_parameters, header),
    //    &header.execution_branch,
    //    floorlog2(EXECUTION_PAYLOAD_INDEX),
    //    get_subtree_index(EXECUTION_PAYLOAD_INDEX),
    //    &header.beacon.body_root,
    //)
    Ok(())
}

pub fn validate_merkle_branch(_leaf: B256) -> Result<(), EthereumIBCError> {
    //let mut root = leaf;
    //for (i, sibling) in siblings.iter().enumerate() {
    //    let index = get_subtree_index(i + 1);
    //    root = if index % 2 == 0 {
    //        hash_nodes(sibling, &root)
    //    } else {
    //        hash_nodes(&root, sibling)
    //    };
    //}
    //
    //ensure(root == root_hash, Error::InvalidMerkleBranch { root_hash, root })
    Ok(())
}

/// Returns the epoch at a given `slot`.
///
/// [See in consensus-spec](https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#compute_epoch_at_slot)
pub fn compute_epoch_at_slot(slots_per_epoch: u64, slot: u64) -> u64 {
    slot / slots_per_epoch
}

#[cfg(test)]
mod test {
    #[test]
    fn test_is_valid_ligth_client_header() {
        // we are going to use the example from a light client header where
        // the leaf is the light client execution root
        // the branch is the light client execution branch
        // the depth is floorlog2 of execution payload index
        // the index is the subtree index of the execution payload index
        // the root is the beacon body root
    }
}

use alloy_primitives::{Bloom, Bytes, B256};
use serde::{Deserialize, Serialize};
use tree_hash::{MerkleHasher, TreeHash, BYTES_PER_CHUNK};

use crate::config::consts::{floorlog2, EXECUTION_PAYLOAD_INDEX};

use super::bls::BlsPublicKey;

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

        hasher.finish().unwrap()
    }
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
        let leaves = (self.0.len() + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK;
        let mut hasher = MerkleHasher::with_leaves(leaves);

        for item in &self.0 {
            hasher.write(item.tree_hash_root()[..1].as_ref()).unwrap()
        }

        hasher.finish().unwrap()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct VecBlsPublicKey(pub Vec<BlsPublicKey>);

impl TreeHash for VecBlsPublicKey {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        let leaves = (self.0.len() + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK;
        let mut hasher = MerkleHasher::with_leaves(leaves);

        for item in &self.0 {
            hasher.write(item.tree_hash_root()[..1].as_ref()).unwrap()
        }

        hasher.finish().unwrap()
    }
}

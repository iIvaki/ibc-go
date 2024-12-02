use alloy_primitives::B256;
use cosmwasm_std::{Binary, CustomQuery, Deps, QueryRequest};
use ethereum::{
    extras::utils::ensure,
    types::bls::{BlsPublicKey, BlsSignature, BlsVerify},
    utils::hex::to_hex,
};
use thiserror::Error;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum UnionCustomQuery {
    AggregateVerify {
        public_keys: Vec<Binary>,
        message: Binary,
        signature: Binary,
    },
    Aggregate {
        public_keys: Vec<Binary>,
    },
}

impl CustomQuery for UnionCustomQuery {}

pub struct BlsVerifier<'a> {
    pub deps: Deps<'a, UnionCustomQuery>,
}

#[derive(Debug, PartialEq, thiserror::Error, Clone)]
#[error("signature cannot be verified (public_keys: {public_keys:?}, msg: {msg}, signature: {signature})", msg = to_hex(.msg))]
pub struct InvalidSignatureErr {
    pub public_keys: Vec<BlsPublicKey>,
    pub msg: B256,
    pub signature: BlsSignature,
}

#[derive(Error, Debug)]
pub enum BlsVerifierError {
    #[error("fast aggregate verify error: {0}")]
    FastAggregateVerify(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(InvalidSignatureErr),
}

impl<'a> BlsVerify for BlsVerifier<'a> {
    type Error = BlsVerifierError;

    fn fast_aggregate_verify(
        &self,
        public_keys: Vec<&BlsPublicKey>,
        msg: B256,
        signature: BlsSignature,
    ) -> Result<(), Self::Error> {
        let binary_public_keys: Vec<Binary> = public_keys
            .clone()
            .into_iter()
            .map(|p| Binary::from(p.to_vec()))
            .collect();

        let request: QueryRequest<UnionCustomQuery> =
            QueryRequest::Custom(UnionCustomQuery::AggregateVerify {
                public_keys: binary_public_keys,
                message: Binary::from(msg.to_vec()),
                signature: Binary::from(signature.to_vec()),
            });
        let is_valid = self
            .deps
            .querier
            .query(&request)
            .map_err(|e| BlsVerifierError::FastAggregateVerify(e.to_string()))?;

        ensure(
            is_valid,
            BlsVerifierError::InvalidSignature(InvalidSignatureErr {
                public_keys: public_keys.into_iter().copied().collect(),
                msg,
                signature,
            }),
        )
    }
}

use alloy_primitives::hex;

pub struct DomainType(pub [u8; 4]);
impl DomainType {
    pub const BEACON_PROPOSER: Self = Self(hex!("00000000"));
    pub const BEACON_ATTESTER: Self = Self(hex!("01000000"));
    pub const RANDAO: Self = Self(hex!("02000000"));
    pub const DEPOSIT: Self = Self(hex!("03000000"));
    pub const VOLUNTARY_EXIT: Self = Self(hex!("04000000"));
    pub const SELECTION_PROOF: Self = Self(hex!("05000000"));
    pub const AGGREGATE_AND_PROOF: Self = Self(hex!("06000000"));
    pub const SYNC_COMMITTEE: Self = Self(hex!("07000000"));
    pub const SYNC_COMMITTEE_SELECTION_PROOF: Self = Self(hex!("08000000"));
    pub const CONTRIBUTION_AND_PROOF: Self = Self(hex!("09000000"));
    pub const BLS_TO_EXECUTION_CHANGE: Self = Self(hex!("0A000000"));
    pub const APPLICATION_MASK: Self = Self(hex!("00000001"));
}

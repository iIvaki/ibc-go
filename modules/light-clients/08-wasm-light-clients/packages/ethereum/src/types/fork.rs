use serde::{Deserialize, Serialize};

use super::wrappers::Version;

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct Fork {
    pub version: Version,
    pub epoch: u64,
}

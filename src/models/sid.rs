// src/models/sid.rs

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecurityIdentifier {
    pub revision: u8,
    pub authority: [u8; 6],
    pub sub_authorities: Vec<u32>,
}
    #[allow(dead_code)]
impl SecurityIdentifier {
    pub fn new_nt_authority(id: u32) -> Self {
        Self {
            revision: 1,
            authority: [0, 0, 0, 0, 0, 5], // SECURITY_NT_AUTHORITY
            sub_authorities: vec![id],
        }
    }

    pub fn new_from_parts(authority: [u8; 6], subs: Vec<u32>) -> Self {
        Self {
            revision: 1,
            authority,
            sub_authorities: subs,
        }
    }

    pub fn to_string(&self) -> String {
        let auth = u64::from_be_bytes([0, 0, 0, 0, 0, 0, self.authority[0], self.authority[1]])
            + (u64::from(self.authority[2]) << 40)
            + (u64::from(self.authority[3]) << 32)
            + (u64::from(self.authority[4]) << 24)
            + (u64::from(self.authority[5]) << 16);
        let subs: Vec<String> = self.sub_authorities.iter().map(|a| a.to_string()).collect();
        format!("S-{}-{}-{}", self.revision, auth, subs.join("-"))
    }
}

impl fmt::Display for SecurityIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}
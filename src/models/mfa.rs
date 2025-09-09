// src/models/mfa.rs

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MfaMethod {
    Totp,
    Sms,
    Fido2,
    EmailOtp,
}
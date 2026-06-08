//! Admin password hashing and verification (bcrypt).
//!
//! Phase 4 keeps the surface tiny: a single hash/verify pair. Session
//! management lives in [`crate::session`].

use bcrypt::{hash, verify, BcryptError, DEFAULT_COST};

pub fn hash_password(plain: &str) -> Result<String, BcryptError> {
    hash(plain, DEFAULT_COST)
}

pub fn verify_password(hashed: &str, plain: &str) -> Result<bool, BcryptError> {
    verify(plain, hashed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_round_trip() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password(&h, "hunter2").unwrap());
        assert!(!verify_password(&h, "wrong").unwrap());
    }
}

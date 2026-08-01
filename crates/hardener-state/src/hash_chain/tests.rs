#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`hash_chain`].
//!
//! Split out of `hash_chain.rs`. This file sits in the `hash_chain/` directory
//! beside it, so `super` still resolves to `crate::hash_chain` and every
//! import carried across unchanged, private items included.

use super::*;

#[test]
fn test_hash_chain_genesis() {
    let chain = HashChain::new();
    assert_eq!(chain.current_hash().len(), 32);
    assert_eq!(chain.current_hash(), &vec![0u8; 32]);
}

#[test]
fn test_hash_chain_progression() {
    let mut chain = HashChain::new();
    let data1 = b"First audit entry";
    let hash1 = chain.next_hash(data1);

    assert_eq!(hash1.len(), 32);
    assert_ne!(hash1, vec![0u8; 32]); // Should be different from genesis

    chain.update(hash1.clone());
    assert_eq!(chain.current_hash(), &hash1);
}

#[test]
fn test_hash_chain_verification() {
    let prev_hash = vec![0u8; 32];
    let data = b"Test audit entry";

    // Compute hash
    let mut combined = prev_hash.clone();
    combined.extend_from_slice(data);
    let correct_hash = digest(&SHA256, &combined).as_ref().to_vec();

    // Verify correct hash
    assert!(HashChain::verify_entry(&prev_hash, data, &correct_hash));

    // Verify tampered hash fails
    let mut tampered_hash = correct_hash.clone();
    tampered_hash[0] ^= 0xFF; // Flip bits
    assert!(!HashChain::verify_entry(&prev_hash, data, &tampered_hash));
}

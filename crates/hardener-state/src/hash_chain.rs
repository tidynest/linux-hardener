use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};

/// Maintains a cryptographic hash chain for tamper-proof audit logging.
///
/// Each entry in the chain depends on the previous entry's hash, making it
/// computationally infeasible to modify historical entries without detection.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HashChain {
    /// The hash of the previous entry in the chain.
    /// For the first entry (genesis), this is a zero-filled 32-bit array.
    previous_hash: Vec<u8>,
}

impl HashChain {
    /// Creates a new hash chain with a genesis (zero) previous hash.
    ///
    /// The genesis entry has no predecessor, so we initialise with 32 zero bytes.
    pub fn new() -> HashChain {
        Self {
            previous_hash: vec![0u8; 32], // SHA-256 produces 32 bytes
        }
    }

    /// Computes the next hash in the chain by combining the previous hash with new data.
    ///
    /// # Arguments
    /// * `data` - The new data to add to the chain (typically serialised audit entry)
    ///
    /// # Returns
    /// The SHA-256 hash that should be stored with this entry and used as the
    /// previous_hash for the next entry,
    pub fn next_hash(&self, data: &[u8]) -> Vec<u8> {
        // Concatenate: previous_hash || data
        let mut combined = self.previous_hash.clone();
        combined.extend_from_slice(data);

        // Hash the combination
        let hash = digest(&SHA256, &combined);
        hash.as_ref().to_vec()
    }

    /// Updates the chain state with a new hash.
    ///
    /// This should be called after successfully writing an audit entry
    /// to update the chain for the next entry.
    ///
    /// # Arguments
    /// * `new_hash` - The hash that was computed for the entry just written
    pub fn update(&mut self, new_hash: Vec<u8>) {
        self.previous_hash = new_hash;
    }

    /// Verifies that a hash was correctly computed from previous hash and data.
    ///
    /// # Arguments
    /// * `previous_hash` - The hash from the previous entry
    /// * `data`          - The data from the current entry
    /// * `claimed_hash`  - The hash stored with the current entry
    ///
    /// # Returns
    /// `true` if the claimed_hash matches what we compute, `false` if tampered
    pub fn verify_entry(previous_hash: &[u8], data: &[u8], claimed_hash: &[u8]) -> bool {
        // Recompute what the hash should be
        let mut combined = previous_hash.to_vec();
        combined.extend_from_slice(data);
        let expected_hash = digest(&SHA256, &combined);

        // Compare with what was claimed
        expected_hash.as_ref() == claimed_hash
    }

    /// Returns the current previous_hash value.
    ///
    /// This is useful when you need to include the hash in serialised data.
    pub fn current_hash(&self) -> &[u8] {
        &self.previous_hash
    }
}

impl Default for HashChain {
    fn default() -> HashChain {
        HashChain::new()
    }
}

#[cfg(test)]
mod tests {
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
}

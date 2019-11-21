extern crate nimiq_block_albatross as block_albatross;
extern crate nimiq_blockchain_albatross as blockchain_albatross;
extern crate nimiq_collections as collections;
extern crate nimiq_hash as hash;
extern crate nimiq_primitives as primitives;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use failure::Fail;

use beserial::Serialize;
use block_albatross::{Block, ForkProof, ForkProofError, MicroBlock};
use blockchain_albatross::Blockchain;
use collections::BitSet;
use hash::{Blake2bHash, Hash};
use primitives::policy;
use primitives::slot::Slot;

pub struct ForkProofPool {
    blockchain: Arc<Blockchain>,
    fork_proofs: HashMap<Blake2bHash, (ForkProof, u16)>,
    fork_proof_slots: HashSet<u16>,
}

#[derive(Debug, Fail)]
pub enum ForkProofPoolError {
    #[fail(display = "This slot has already been slashed")]
    SlotAlreadySlashed,
    #[fail(display = "Fork proof is for a block in a historic or future epoch")]
    InvalidEpochTarget,
    #[fail(display = "Cannot determine slot at fork proof block")]
    UnexpectedBlock,
    #[fail(display = "Fork proof signature is invalid")]
    InvalidProof(ForkProofError),
}

impl ForkProofPool {
    pub fn new(blockchain: Arc<Blockchain>) -> Self {
        ForkProofPool {
            blockchain,
            fork_proofs: HashMap::new(),
            fork_proof_slots: HashSet::new(),
        }
    }

    /// Adds a fork proof if it is not yet part of the pool.
    /// Returns whether it has been added.
    /// TODO: Check what should be an error and what shouldn't.
    pub fn insert(&mut self, fork_proof: ForkProof) -> Result<bool, ForkProofPoolError> {
        // Check whether we already know the proof.
        let hash: Blake2bHash = fork_proof.hash();
        if self.fork_proofs.contains_key(&hash) {
            return Ok(false);
        }

        // Keep the blockchain locked, so that the state does not change while we insert the fork proof.
        let blockchain_state = self.blockchain.state();
        let blockchain_height = blockchain_state.block_number();
        let blockchain_epoch = policy::epoch_at(blockchain_height);

        // Check if proof is valid for this block.
        if !fork_proof.is_valid_at(blockchain_height) {
            return Err(ForkProofPoolError::InvalidEpochTarget);
        }

        let block_number = fork_proof.header1.block_number;
        let view_number = fork_proof.header1.view_number;
        let epoch = policy::epoch_at(block_number);

        let (slot, slot_number) = self.blockchain.get_slot_at(block_number, view_number, None)
            .ok_or(ForkProofPoolError::UnexpectedBlock)?;

        let slashed_set = self.blockchain.slashed_set_for_epoch(epoch)
            .map_err(|_| ForkProofPoolError::InvalidEpochTarget)?;

        // Check that slot has not yet been slashed.
        if slashed_set.contains(slot_number as usize)
            || self.fork_proof_slots.contains(&slot_number) {
            return Err(ForkProofPoolError::SlotAlreadySlashed);
        }

        // Verify fork proof.
        fork_proof.verify(&slot.public_key().uncompress_unchecked())
            .map_err(ForkProofPoolError::InvalidProof)?;

        self.fork_proofs.insert(fork_proof.hash(), (fork_proof, slot_number));
        Ok(self.fork_proof_slots.insert(slot_number))
    }

    /// Checks whether a fork proof is already part of the pool.
    pub fn contains(&self, fork_proof: &ForkProof) -> bool {
        self.contains_hash(&fork_proof.hash())
    }

    /// Checks whether a fork proof is already part of the pool.
    pub fn contains_hash(&self, fork_proof_hash: &Blake2bHash) -> bool {
        self.fork_proofs.contains_key(&fork_proof_hash)
    }

    /// Returns a fork proof by hash.
    pub fn get(&self, fork_proof_hash: &Blake2bHash) -> Option<&ForkProof> {
        self.fork_proofs.get(&fork_proof_hash).map(|(proof, _)| proof)
    }

    /// Remove fork proofs that are not required anymore.
    pub fn housekeeping(&mut self, block_number: u32, current_slashed_set: BitSet, previous_slashed_set: BitSet) {
        let current_epoch = policy::epoch_at(block_number);
        self.fork_proofs.retain(|hash, (fork_proof, slot_number)| {
            if !fork_proof.is_valid_at(block_number) {
                return false;
            }

            // Remove fork proofs for validators that have been slashed by other means.
            if policy::epoch_at(fork_proof.header1.block_number) == current_epoch {
                !current_slashed_set.contains(*slot_number as usize)
            } else {
                !previous_slashed_set.contains(*slot_number as usize)
            }
        });
    }

    /// Applies a block to the pool, removing processed fork proofs.
    pub fn apply_block(&mut self, block: &Block) {
        if let Block::Micro(MicroBlock { extrinsics: Some(extrinsics), .. }) = block {
            for fork_proof in extrinsics.fork_proofs.iter() {
                if let Some((_, slot_number)) = self.fork_proofs.remove(&fork_proof.hash()) {
                    self.fork_proof_slots.remove(&slot_number);
                }
            }
        }
    }

    /// Reverts a block, re-adding fork proofs.
    pub fn revert_block(&mut self, block: &Block) {
        if let Block::Micro(MicroBlock { extrinsics: Some(extrinsics), .. }) = block {
            for fork_proof in extrinsics.fork_proofs.iter() {
                // This happens less frequently, so we can use the blockchain here.
                // TODO: Check for deadlocks!
                let block_number = fork_proof.header1.block_number;
                let view_number = fork_proof.header1.view_number;
                let epoch = policy::epoch_at(block_number);

                // Skip fork proofs for which slot cannot be determined.
                if let Some((_, slot_number)) = self.blockchain.get_slot_at(block_number, view_number, None) {
                    self.fork_proofs.insert(fork_proof.hash(), (fork_proof.clone(), slot_number));
                    self.fork_proof_slots.insert(slot_number);
                }
            }
        }
    }

    /// Returns a list of current fork proofs.
    pub fn get_fork_proofs_for_block(&self, max_size: usize) -> Vec<ForkProof> {
        let mut proofs = Vec::new();
        let mut size = 0;
        for (proof, _) in self.fork_proofs.values() {
            if size + proof.serialized_size() < max_size {
                proofs.push(proof.clone());
                size += proof.serialized_size();
            }
        }
        proofs
    }
}

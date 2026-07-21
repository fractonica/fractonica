//! Deterministic anti-entropy inventories for Fractonica spaces.
//!
//! The inventory is an eight-way Merkle radix tree over immutable 256-bit
//! identifiers. Unlike position-based chunks, its branches do not shift when
//! two offline nodes insert different operations in different orders.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const RADIX: usize = 8;
pub const BUCKET_CAPACITY: usize = 8;
pub const KEY_BYTES: usize = 32;
pub const MAX_OCTAL_DEPTH: usize = 86;
pub const MAX_NAMESPACE_BYTES: usize = 32;

pub type InventoryDigest = [u8; 32];

const EMPTY_DOMAIN: &[u8] = b"fractonica.inventory.empty.v1\0";
const LEAF_DOMAIN: &[u8] = b"fractonica.inventory.leaf.v1\0";
const NODE_DOMAIN: &[u8] = b"fractonica.inventory.node.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct InventoryEntry {
    /// Stable immutable identifier, such as an operation ID or content ID.
    pub key: [u8; KEY_BYTES],
    /// Digest of the canonical object bytes. Keeping this separate makes the
    /// primitive usable when the identifier is not itself a content digest.
    pub value_digest: InventoryDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryChild {
    pub digit: u8,
    pub count: u64,
    pub hash: InventoryDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventorySummary {
    /// MSB-first octal path. At depth 85 only digits 0 and 4 are reachable,
    /// because a 256-bit key has one final bit after 85 complete triplets.
    pub prefix: Vec<u8>,
    pub count: u64,
    pub hash: InventoryDigest,
    /// Present while this bucket is larger than `BUCKET_CAPACITY`.
    pub children: Vec<InventoryChild>,
    /// Present when the complete bucket can be transferred directly.
    pub entries: Vec<InventoryEntry>,
}

#[derive(Clone, Debug)]
pub struct InventoryTree {
    namespace: Vec<u8>,
    entries: Vec<InventoryEntry>,
}

impl InventoryTree {
    pub fn build(
        namespace: impl Into<Vec<u8>>,
        entries: impl IntoIterator<Item = InventoryEntry>,
    ) -> Result<Self, InventoryError> {
        let namespace = namespace.into();
        if namespace.is_empty() || namespace.len() > MAX_NAMESPACE_BYTES {
            return Err(InventoryError::InvalidNamespace);
        }
        let mut unique = BTreeMap::new();
        for entry in entries {
            if let Some(existing) = unique.insert(entry.key, entry.value_digest)
                && existing != entry.value_digest
            {
                return Err(InventoryError::ConflictingEntry(entry.key));
            }
        }
        Ok(Self {
            namespace,
            entries: unique
                .into_iter()
                .map(|(key, value_digest)| InventoryEntry { key, value_digest })
                .collect(),
        })
    }

    pub fn root(&self) -> InventorySummary {
        self.summary(&[]).expect("the empty prefix is valid")
    }

    pub fn summary(&self, prefix: &[u8]) -> Result<InventorySummary, InventoryError> {
        validate_prefix(prefix)?;
        let entries = self
            .entries
            .iter()
            .copied()
            .filter(|entry| key_has_prefix(&entry.key, prefix))
            .collect::<Vec<_>>();
        Ok(self.summarize_entries(prefix, &entries))
    }

    fn summarize_entries(&self, prefix: &[u8], entries: &[InventoryEntry]) -> InventorySummary {
        if entries.len() <= BUCKET_CAPACITY || prefix.len() == MAX_OCTAL_DEPTH {
            return InventorySummary {
                prefix: prefix.to_vec(),
                count: entries.len() as u64,
                hash: bucket_hash(&self.namespace, prefix, entries),
                children: Vec::new(),
                entries: entries.to_vec(),
            };
        }

        let mut children = Vec::new();
        for digit in 0..RADIX as u8 {
            let child_entries = entries
                .iter()
                .copied()
                .filter(|entry| octal_digit(&entry.key, prefix.len()) == digit)
                .collect::<Vec<_>>();
            if child_entries.is_empty() {
                continue;
            }
            let mut child_prefix = prefix.to_vec();
            child_prefix.push(digit);
            let child = self.summarize_entries(&child_prefix, &child_entries);
            children.push(InventoryChild {
                digit,
                count: child.count,
                hash: child.hash,
            });
        }
        InventorySummary {
            prefix: prefix.to_vec(),
            count: entries.len() as u64,
            hash: node_hash(&self.namespace, prefix, entries.len() as u64, &children),
            children,
            entries: Vec::new(),
        }
    }
}

fn bucket_hash(namespace: &[u8], prefix: &[u8], entries: &[InventoryEntry]) -> InventoryDigest {
    if entries.is_empty() {
        return digest_parts(EMPTY_DOMAIN, namespace, prefix, 0, &[]);
    }
    let mut leaves = Vec::with_capacity(entries.len() * 64);
    for entry in entries {
        let mut leaf = Sha256::new();
        leaf.update(LEAF_DOMAIN);
        leaf.update((namespace.len() as u16).to_be_bytes());
        leaf.update(namespace);
        leaf.update(entry.key);
        leaf.update(entry.value_digest);
        leaves.extend_from_slice(&leaf.finalize());
    }
    digest_parts(
        NODE_DOMAIN,
        namespace,
        prefix,
        entries.len() as u64,
        &leaves,
    )
}

fn node_hash(
    namespace: &[u8],
    prefix: &[u8],
    count: u64,
    children: &[InventoryChild],
) -> InventoryDigest {
    let mut encoded = Vec::with_capacity(children.len() * 41);
    for child in children {
        encoded.push(child.digit);
        encoded.extend_from_slice(&child.count.to_be_bytes());
        encoded.extend_from_slice(&child.hash);
    }
    digest_parts(NODE_DOMAIN, namespace, prefix, count, &encoded)
}

fn digest_parts(
    domain: &[u8],
    namespace: &[u8],
    prefix: &[u8],
    count: u64,
    payload: &[u8],
) -> InventoryDigest {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((namespace.len() as u16).to_be_bytes());
    digest.update(namespace);
    digest.update((prefix.len() as u16).to_be_bytes());
    digest.update(prefix);
    digest.update(count.to_be_bytes());
    digest.update(payload);
    digest.finalize().into()
}

fn validate_prefix(prefix: &[u8]) -> Result<(), InventoryError> {
    if prefix.len() > MAX_OCTAL_DEPTH || prefix.iter().any(|digit| *digit >= RADIX as u8) {
        return Err(InventoryError::InvalidPrefix);
    }
    if prefix.len() == MAX_OCTAL_DEPTH && !matches!(prefix.last(), Some(0 | 4)) {
        return Err(InventoryError::InvalidPrefix);
    }
    Ok(())
}

fn key_has_prefix(key: &[u8; KEY_BYTES], prefix: &[u8]) -> bool {
    prefix
        .iter()
        .enumerate()
        .all(|(depth, digit)| octal_digit(key, depth) == *digit)
}

fn octal_digit(key: &[u8; KEY_BYTES], depth: usize) -> u8 {
    let start_bit = depth * 3;
    let mut digit = 0_u8;
    for offset in 0..3 {
        digit <<= 1;
        let bit = start_bit + offset;
        if bit < KEY_BYTES * 8 {
            digit |= (key[bit / 8] >> (7 - (bit % 8))) & 1;
        }
    }
    digit
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum InventoryError {
    #[error("inventory namespace must contain 1-{MAX_NAMESPACE_BYTES} bytes")]
    InvalidNamespace,
    #[error("inventory prefix is not a canonical MSB-first octal path")]
    InvalidPrefix,
    #[error("inventory key has conflicting canonical digests")]
    ConflictingEntry([u8; KEY_BYTES]),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: u8, value: u8) -> InventoryEntry {
        let mut id = [0_u8; 32];
        id[0] = key;
        InventoryEntry {
            key: id,
            value_digest: [value; 32],
        }
    }

    #[test]
    fn insertion_order_and_duplicates_do_not_change_the_root() {
        let forward = InventoryTree::build("operations", (0..20).map(|n| entry(n, n))).unwrap();
        let reverse =
            InventoryTree::build("operations", (0..20).rev().map(|n| entry(n, n))).unwrap();
        let duplicate =
            InventoryTree::build("operations", (0..20).chain(0..20).map(|n| entry(n, n))).unwrap();
        assert_eq!(forward.root(), reverse.root());
        assert_eq!(forward.root(), duplicate.root());
    }

    #[test]
    fn one_offline_edit_changes_only_its_stable_radix_branch() {
        let original = InventoryTree::build("operations", (0..20).map(|n| entry(n, n))).unwrap();
        let changed = InventoryTree::build(
            "operations",
            (0..20).map(|n| if n == 17 { entry(n, 99) } else { entry(n, n) }),
        )
        .unwrap();
        let original_root = original.root();
        let changed_root = changed.root();
        assert_ne!(original_root.hash, changed_root.hash);
        assert_eq!(original_root.count, changed_root.count);
        let different = original_root
            .children
            .iter()
            .zip(&changed_root.children)
            .filter(|(left, right)| left.hash != right.hash)
            .count();
        assert_eq!(different, 1);
    }

    #[test]
    fn small_subtrees_are_complete_transfer_buckets() {
        let tree = InventoryTree::build("operations", (0..8).map(|n| entry(n, n))).unwrap();
        let root = tree.root();
        assert_eq!(root.entries.len(), BUCKET_CAPACITY);
        assert!(root.children.is_empty());
    }

    #[test]
    fn namespaces_and_values_are_bound_into_the_hash() {
        let operation = InventoryTree::build("operations", [entry(1, 2)]).unwrap();
        let content = InventoryTree::build("content", [entry(1, 2)]).unwrap();
        let changed = InventoryTree::build("operations", [entry(1, 3)]).unwrap();
        assert_ne!(operation.root().hash, content.root().hash);
        assert_ne!(operation.root().hash, changed.root().hash);
    }
}

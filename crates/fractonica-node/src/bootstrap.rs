//! Compatibility re-export for node bootstrap callers.
//!
//! The canonical builder lives in a portable crate so standalone clients and
//! headless nodes construct byte-identical personal-space trust anchors.

pub use fractonica_space_bootstrap::*;

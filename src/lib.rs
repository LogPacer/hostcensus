//! hostcensus takes a census of one host and writes it to a bundle file.
//!
//! The bundle format is the contract: see `docs/bundle-format.md`.

pub mod bundle;
pub mod census;
pub mod glob;
pub mod handover;
pub mod host;
pub mod inventory;
pub mod mark;
pub mod output;
pub mod scanners;
pub mod timestamp;

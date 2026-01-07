//! Generic TDX types and utilities.
//!
//! This module provides base types and functions for TDX attestation verification
//! that are not specific to any particular TDX deployment platform.

pub mod config;

pub use config::{ExpectedBootchain, TCB_STATUS_LIST};

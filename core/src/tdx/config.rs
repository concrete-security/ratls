//! Generic TDX configuration types.

use serde::{Deserialize, Serialize};

/// Expected bootchain measurements for verification.
///
/// These measurements represent the known-good values for the TDX bootchain
/// components that should be verified during attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedBootchain {
    /// MRTD - Initial TD memory contents (TDVF/firmware).
    ///
    /// This is the hash of the initial TD memory layout, including the
    /// firmware/TDVF that runs before the OS kernel.
    pub mrtd: String,

    /// RTMR0 - Virtual hardware environment.
    ///
    /// Measures the virtual hardware configuration and TD configuration.
    pub rtmr0: String,

    /// RTMR1 - Linux kernel.
    ///
    /// Measures the Linux kernel that is loaded into the TD.
    pub rtmr1: String,

    /// RTMR2 - Kernel cmdline + initramfs.
    ///
    /// Measures the kernel command line parameters and initial ramdisk.
    pub rtmr2: String,
}

/// Known TCB status values from Intel DCAP.
pub const TCB_STATUS_LIST: &[&str] = &[
    "UpToDate",
    "OutOfDate",
    "ConfigurationNeeded",
    "TDRelaunchAdvised",
    "SWHardeningNeeded",
    "Revoked",
];

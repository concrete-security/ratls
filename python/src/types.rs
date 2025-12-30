use pyo3::prelude::*;
use ratls_core::{AttestationResult, Policy, TeeType};

/// Supported TEE types.
#[pyclass(name = "TeeType", eq, eq_int)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PyTeeType {
    #[pyo3(name = "TDX")]
    Tdx = 0,
}

impl From<TeeType> for PyTeeType {
    fn from(t: TeeType) -> Self {
        match t {
            TeeType::Tdx => PyTeeType::Tdx,
        }
    }
}

impl From<PyTeeType> for TeeType {
    fn from(t: PyTeeType) -> Self {
        match t {
            PyTeeType::Tdx => TeeType::Tdx,
        }
    }
}

/// TDX TCB policy constraints.
#[pyclass(name = "TdxTcbPolicy")]
#[derive(Clone, Default)]
pub struct PyTdxTcbPolicy {
    #[pyo3(get, set)]
    pub mrseam: Option<Vec<u8>>,
    #[pyo3(get, set)]
    pub mrtmrs: Option<Vec<u8>>,
}

#[pymethods]
impl PyTdxTcbPolicy {
    #[new]
    #[pyo3(signature = (mrseam=None, mrtmrs=None))]
    fn new(mrseam: Option<Vec<u8>>, mrtmrs: Option<Vec<u8>>) -> Self {
        Self { mrseam, mrtmrs }
    }
}

impl From<PyTdxTcbPolicy> for ratls_core::TdxTcbPolicy {
    fn from(p: PyTdxTcbPolicy) -> Self {
        ratls_core::TdxTcbPolicy {
            mrseam: p.mrseam,
            mrtmrs: p.mrtmrs,
        }
    }
}

impl From<ratls_core::TdxTcbPolicy> for PyTdxTcbPolicy {
    fn from(p: ratls_core::TdxTcbPolicy) -> Self {
        PyTdxTcbPolicy {
            mrseam: p.mrseam,
            mrtmrs: p.mrtmrs,
        }
    }
}

/// Attestation policy describing acceptable TEEs.
#[pyclass(name = "Policy")]
#[derive(Clone)]
pub struct PyPolicy {
    #[pyo3(get, set)]
    pub tee_type: PyTeeType,
    #[pyo3(get, set)]
    pub min_tdx_tcb: Option<PyTdxTcbPolicy>,
    #[pyo3(get, set)]
    pub allowed_tdx_status: Vec<String>,
    #[pyo3(get, set)]
    pub pccs_url: Option<String>,
}

#[pymethods]
impl PyPolicy {
    #[new]
    #[pyo3(signature = (
        tee_type=PyTeeType::Tdx,
        min_tdx_tcb=None,
        allowed_tdx_status=None,
        pccs_url=None
    ))]
    fn new(
        tee_type: PyTeeType,
        min_tdx_tcb: Option<PyTdxTcbPolicy>,
        allowed_tdx_status: Option<Vec<String>>,
        pccs_url: Option<String>,
    ) -> Self {
        Self {
            tee_type,
            min_tdx_tcb,
            allowed_tdx_status: allowed_tdx_status
                .unwrap_or_else(|| vec!["UpToDate".into()]),
            pccs_url: pccs_url.or_else(|| {
                Some("https://pccs.phala.network/tdx/certification/v4".into())
            }),
        }
    }

    /// Create a default policy requiring UpToDate TCB status.
    #[staticmethod]
    #[pyo3(name = "default")]
    pub fn py_default() -> Self {
        Policy::default().into()
    }

    /// Create a relaxed policy for development environments.
    #[staticmethod]
    pub fn dev_tdx() -> Self {
        Policy::dev_tdx().into()
    }
}

impl From<Policy> for PyPolicy {
    fn from(p: Policy) -> Self {
        PyPolicy {
            tee_type: p.tee_type.into(),
            min_tdx_tcb: p.min_tdx_tcb.map(Into::into),
            allowed_tdx_status: p.allowed_tdx_status,
            pccs_url: p.pccs_url,
        }
    }
}

impl From<PyPolicy> for Policy {
    fn from(p: PyPolicy) -> Self {
        Policy {
            tee_type: p.tee_type.into(),
            min_tdx_tcb: p.min_tdx_tcb.map(Into::into),
            allowed_tdx_status: p.allowed_tdx_status,
            pccs_url: p.pccs_url,
        }
    }
}

/// Result of attestation verification.
#[pyclass(name = "AttestationResult")]
#[derive(Clone)]
pub struct PyAttestationResult {
    #[pyo3(get)]
    pub trusted: bool,
    #[pyo3(get)]
    pub tee_type: PyTeeType,
    #[pyo3(get)]
    pub measurement: Option<String>,
    #[pyo3(get)]
    pub tcb_status: String,
    #[pyo3(get)]
    pub advisory_ids: Vec<String>,
}

#[pymethods]
impl PyAttestationResult {
    fn __repr__(&self) -> String {
        format!(
            "AttestationResult(trusted={}, tee_type={:?}, measurement={:?}, tcb_status={:?})",
            self.trusted,
            self.tee_type,
            self.measurement,
            self.tcb_status
        )
    }
}

impl From<AttestationResult> for PyAttestationResult {
    fn from(r: AttestationResult) -> Self {
        PyAttestationResult {
            trusted: r.trusted,
            tee_type: r.tee_type.into(),
            measurement: r.measurement,
            tcb_status: r.tcb_status,
            advisory_ids: r.advisory_ids,
        }
    }
}

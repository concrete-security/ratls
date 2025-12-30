use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use ratls_core::RatlsError;

// Define Python exception hierarchy
create_exception!(ratls, RatlsException, PyException, "Base exception for RATLS errors.");
create_exception!(ratls, PolicyViolationError, RatlsException, "Attestation policy was violated.");
create_exception!(ratls, VendorVerificationError, RatlsException, "Quote verification failed.");
create_exception!(ratls, IoError, RatlsException, "I/O error during attestation.");
create_exception!(ratls, X509Error, RatlsException, "X.509 certificate parsing error.");
create_exception!(ratls, TeeUnsupportedError, RatlsException, "Unsupported TEE type.");

/// Convert a string error message to a Python exception.
pub fn to_py_error(msg: impl ToString) -> PyErr {
    RatlsException::new_err(msg.to_string())
}

/// Convert a RatlsError to a Python exception.
pub fn ratls_error_to_py(err: RatlsError) -> PyErr {
    match &err {
        RatlsError::Policy(_) => PolicyViolationError::new_err(err.to_string()),
        RatlsError::Vendor(_) => VendorVerificationError::new_err(err.to_string()),
        RatlsError::Io(_) => IoError::new_err(err.to_string()),
        RatlsError::X509(_) => X509Error::new_err(err.to_string()),
        RatlsError::TeeUnsupported(_) => TeeUnsupportedError::new_err(err.to_string()),
    }
}

/// Register exception types with the Python module.
pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("RatlsException", m.py().get_type::<RatlsException>())?;
    m.add("PolicyViolationError", m.py().get_type::<PolicyViolationError>())?;
    m.add("VendorVerificationError", m.py().get_type::<VendorVerificationError>())?;
    m.add("IoError", m.py().get_type::<IoError>())?;
    m.add("X509Error", m.py().get_type::<X509Error>())?;
    m.add("TeeUnsupportedError", m.py().get_type::<TeeUnsupportedError>())?;
    Ok(())
}

"""Tests for RATLS verification"""

import socket
import ssl
import pytest


SERVER_HOST = "vllm.concrete-security.com"
SERVER_PORT = 443


@pytest.fixture
def ssl_socket():
    """Create an SSL socket connected to the test server."""
    context = ssl.create_default_context()
    sock = socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=30)
    ssl_sock = context.wrap_socket(sock, server_hostname=SERVER_HOST)
    yield ssl_sock
    ssl_sock.close()


class TestVerifyAttestationOverSocket:
    """Tests for verify_attestation_over_socket function."""

    def test_verify_with_default_policy(self, ssl_socket):
        """Test verification with default policy."""
        import ratls

        result = ratls.verify_attestation_over_socket(
            ssl_socket,
            policy=ratls.Policy.default(),
            endpoint="/tdx_quote",
            host=SERVER_HOST,
        )

        assert result.trusted is True
        assert result.tee_type == ratls.TeeType.TDX
        assert result.measurement is not None
        assert len(result.measurement) > 0
        assert result.tcb_status is not None

    def test_verify_with_dev_policy(self, ssl_socket):
        """Test verification with relaxed dev policy."""
        import ratls

        result = ratls.verify_attestation_over_socket(
            ssl_socket,
            policy=ratls.Policy.dev_tdx(),
            endpoint="/tdx_quote",
            host=SERVER_HOST,
        )

        assert result.trusted is True
        assert result.tee_type == ratls.TeeType.TDX

    def test_verify_without_policy(self, ssl_socket):
        """Test verification without explicit policy (uses default)."""
        import ratls

        result = ratls.verify_attestation_over_socket(
            ssl_socket,
            endpoint="/tdx_quote",
            host=SERVER_HOST,
        )

        assert result.trusted is True

    def test_socket_remains_usable_after_verification(self, ssl_socket):
        """Test that the socket can be used for HTTP after verification."""
        import ratls

        # First, verify attestation
        result = ratls.verify_attestation_over_socket(
            ssl_socket,
            policy=ratls.Policy.dev_tdx(),
            endpoint="/tdx_quote",
            host=SERVER_HOST,
        )
        assert result.trusted is True

        # Now use the socket for an HTTP request
        request = (
            f"GET /health HTTP/1.1\r\n"
            f"Host: {SERVER_HOST}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        ssl_socket.sendall(request.encode())

        # Read response
        response = b""
        while True:
            chunk = ssl_socket.recv(4096)
            if not chunk:
                break
            response += chunk

        # Should get some HTTP response
        assert b"HTTP/1.1" in response or b"HTTP/1.0" in response


class TestPolicy:
    """Tests for Policy class."""

    def test_default_policy(self):
        """Test default policy creation."""
        import ratls

        policy = ratls.Policy.default()
        assert policy.tee_type == ratls.TeeType.TDX
        assert "UpToDate" in policy.allowed_tdx_status
        assert policy.pccs_url is not None

    def test_dev_tdx_policy(self):
        """Test dev_tdx policy has relaxed status requirements."""
        import ratls

        policy = ratls.Policy.dev_tdx()
        assert policy.tee_type == ratls.TeeType.TDX
        assert len(policy.allowed_tdx_status) > 1
        assert "UpToDate" in policy.allowed_tdx_status
        assert "OutOfDate" in policy.allowed_tdx_status

    def test_custom_policy(self):
        """Test creating a custom policy."""
        import ratls

        policy = ratls.Policy(
            tee_type=ratls.TeeType.TDX,
            allowed_tdx_status=["UpToDate", "SWHardeningNeeded"],
            pccs_url="https://custom.pccs.example.com",
        )
        assert policy.tee_type == ratls.TeeType.TDX
        assert policy.allowed_tdx_status == ["UpToDate", "SWHardeningNeeded"]
        assert policy.pccs_url == "https://custom.pccs.example.com"


class TestAttestationResult:
    """Tests for AttestationResult class."""

    def test_result_attributes(self, ssl_socket):
        """Test that AttestationResult has expected attributes."""
        import ratls

        result = ratls.verify_attestation_over_socket(
            ssl_socket,
            policy=ratls.Policy.dev_tdx(),
            endpoint="/tdx_quote",
            host=SERVER_HOST,
        )

        # Check all attributes are accessible
        assert isinstance(result.trusted, bool)
        assert result.tee_type == ratls.TeeType.TDX
        assert result.measurement is None or isinstance(result.measurement, str)
        assert isinstance(result.tcb_status, str)
        assert isinstance(result.advisory_ids, list)

    def test_result_repr(self, ssl_socket):
        """Test AttestationResult string representation."""
        import ratls

        result = ratls.verify_attestation_over_socket(
            ssl_socket,
            policy=ratls.Policy.dev_tdx(),
            endpoint="/tdx_quote",
            host=SERVER_HOST,
        )

        repr_str = repr(result)
        assert "AttestationResult" in repr_str
        assert "trusted=" in repr_str


class TestExceptions:
    """Tests for exception types."""

    def test_exception_hierarchy(self):
        """Test that exception types exist and have correct hierarchy."""
        import ratls

        # All exceptions should be importable
        assert ratls.RatlsException is not None
        assert ratls.PolicyViolationError is not None
        assert ratls.VendorVerificationError is not None
        assert ratls.IoError is not None
        assert ratls.X509Error is not None
        assert ratls.TeeUnsupportedError is not None

        # All should be subclasses of RatlsException
        assert issubclass(ratls.PolicyViolationError, ratls.RatlsException)
        assert issubclass(ratls.VendorVerificationError, ratls.RatlsException)
        assert issubclass(ratls.IoError, ratls.RatlsException)

    def test_invalid_endpoint_raises_error(self, ssl_socket):
        """Test that an invalid endpoint raises an appropriate error."""
        import ratls

        with pytest.raises(ratls.RatlsException):
            ratls.verify_attestation_over_socket(
                ssl_socket,
                policy=ratls.Policy.dev_tdx(),
                endpoint="/nonexistent_endpoint",
                host=SERVER_HOST,
            )


class TestTeeType:
    """Tests for TeeType enum."""

    def test_tdx_type(self):
        """Test TDX type exists."""
        import ratls

        assert ratls.TeeType.TDX is not None
        assert ratls.TeeType.TDX == ratls.TeeType.TDX


class TestLowLevelFunctions:
    """Tests for low-level verification functions."""

    def test_verify_quote_freshness_invalid_quote(self):
        """Test that invalid quote hex raises error."""
        import ratls

        with pytest.raises(ratls.RatlsException):
            ratls.verify_quote_freshness("invalid_hex!", "nonce")

    def test_verify_event_log_integrity_invalid_quote(self):
        """Test that invalid quote hex raises error."""
        import ratls

        with pytest.raises(ratls.RatlsException):
            ratls.verify_event_log_integrity("invalid_hex!", [])

    def test_verify_tls_certificate_in_log_empty(self):
        """Test verification with empty event log."""
        import ratls

        with pytest.raises(ratls.RatlsException):
            ratls.verify_tls_certificate_in_log([], b"cert_data")

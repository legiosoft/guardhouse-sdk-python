"""Unit tests for TokenVerifier."""

import json
import time
from unittest.mock import Mock, patch

import freezegun
import httpx
import jwt
import pytest
import responses

from guardhouse.constants import Algorithms, Defaults, Endpoints
from guardhouse.exceptions import (
    InvalidAlgorithmError,
    JWKSFetchError,
    ScopeError,
    TokenExpiredError,
    TokenValidationError,
)
from guardhouse.verifier import TokenVerifier


@pytest.fixture
def mock_jwks_response():
    """Mock JWKS response with RSA key."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
        .strip()
    )

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    number_bytes = private_key.public_key().public_numbers()
    n = format(number_bytes.n, "x")
    e = format(number_bytes.e, "x")

    import base64

    def base64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    n_b64 = base64url_encode(number_bytes.n.to_bytes((number_bytes.n.bit_length() + 7) // 8, "big"))
    e_b64 = base64url_encode(number_bytes.e.to_bytes((number_bytes.e.bit_length() + 7) // 8, "big"))

    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-id",
                "alg": "RS256",
                "n": n_b64,
                "e": e_b64,
            }
        ]
    }

    return {
        "jwks": jwks,
        "private_key": private_key,
    }


@pytest.fixture
def token_verifier(mock_jwks_response):
    """Create TokenVerifier instance with mocked JWKS."""

    with responses.RequestsMock() as rsps:
        rsps.add(
            responses.GET,
            "https://auth.example.com/.well-known/jwks.json",
            json=mock_jwks_response["jwks"],
            status=200,
        )

        verifier = TokenVerifier(
            authority="https://auth.example.com",
            audience="my-api",
            validation_mode="jwt_signature",
        )
        yield verifier


@pytest.fixture
def valid_token(mock_jwks_response):
    """Create a valid JWT token."""

    def _create_token(
        exp: int | None = None,
        iss: str = "https://auth.example.com",
        aud: str = "my-api",
        sub: str = "user123",
    ):
        payload = {
            "iss": iss,
            "aud": aud,
            "sub": sub,
            "scope": "read write",
            "iat": int(time.time()),
        }
        if exp is not None:
            payload["exp"] = exp
        else:
            payload["exp"] = int(time.time()) + 3600

        return jwt.encode(
            payload,
            mock_jwks_response["private_key"],
            algorithm="RS256",
            headers={"kid": "test-key-id"},
        )

    return _create_token


class TestTokenVerifierInitialization:
    """Tests for TokenVerifier initialization."""

    def test_init_jwt_signature_mode(self):
        """Test initialization with JWT signature mode."""
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "https://auth.example.com/.well-known/jwks.json",
                json={"keys": []},
                status=200,
            )

            verifier = TokenVerifier(
                authority="https://auth.example.com",
                audience="my-api",
                validation_mode="jwt_signature",
            )

            assert verifier.options.authority == "https://auth.example.com"
            assert verifier.options.audience == "my-api"
            assert verifier.options.validation_mode == "jwt_signature"

    def test_init_introspection_mode_valid(self):
        """Test initialization with introspection mode with valid credentials."""
        verifier = TokenVerifier(
            authority="https://auth.example.com",
            audience="my-api",
            validation_mode="introspection",
            introspection_client_id="introspection-client",
            introspection_client_secret="introspection-secret",
        )

        assert verifier.options.validation_mode == "introspection"

    def test_init_introspection_mode_invalid(self):
        """Test initialization with introspection mode without credentials."""
        with pytest.raises(Exception):
            TokenVerifier(
                authority="https://auth.example.com",
                audience="my-api",
                validation_mode="introspection",
            )


class TestTokenVerification:
    """Tests for token verification."""

    def test_verify_valid_token(self, token_verifier, valid_token):
        """Test verifying a valid token."""
        token = valid_token()
        claims = token_verifier.verify(token)

        assert claims["iss"] == "https://auth.example.com"
        assert claims["aud"] == "my-api"
        assert claims["sub"] == "user123"
        assert claims["scope"] == "read write"

    def test_verify_expired_token(self, token_verifier, valid_token):
        """Test verifying an expired token."""
        token = valid_token(exp=int(time.time()) - 3600)

        with pytest.raises(TokenExpiredError):
            token_verifier.verify(token)

    def test_verify_invalid_issuer(self, token_verifier, valid_token):
        """Test verifying a token with invalid issuer."""
        token = valid_token(iss="https://wrong-issuer.com")

        with pytest.raises(TokenValidationError):
            token_verifier.verify(token)

    def test_verify_invalid_audience(self, token_verifier, valid_token):
        """Test verifying a token with invalid audience."""
        token = valid_token(aud="wrong-audience")

        with pytest.raises(TokenValidationError):
            token_verifier.verify(token)

    def test_verify_none_algorithm(self):
        """Test verifying a token with 'none' algorithm."""
        token = jwt.encode(
            {"iss": "https://auth.example.com", "aud": "my-api", "exp": int(time.time()) + 3600},
            "",
            algorithm="none",
        )

        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "https://auth.example.com/.well-known/jwks.json",
                json={"keys": []},
                status=200,
            )

            verifier = TokenVerifier(
                authority="https://auth.example.com",
                audience="my-api",
                validation_mode="jwt_signature",
            )

            with pytest.raises(InvalidAlgorithmError):
                verifier.verify(token)

    def test_verify_invalid_token_format(self, token_verifier):
        """Test verifying an invalid token format."""
        invalid_token = "not-a-jwt-token"

        with pytest.raises(TokenValidationError):
            token_verifier.verify(invalid_token)

    def test_verify_empty_token(self, token_verifier):
        """Test verifying an empty token."""
        with pytest.raises(TokenValidationError):
            token_verifier.verify("")


class TestScopeChecking:
    """Tests for scope checking."""

    def test_has_scope_with_string_claim(self):
        """Test checking scope with string claim."""
        scope_claim = "read write delete"
        assert TokenVerifier.has_scope("read", scope_claim) is True
        assert TokenVerifier.has_scope("admin", scope_claim) is False

    def test_has_scope_with_list_claim(self):
        """Test checking scope with list claim."""
        scope_claim = ["read", "write", "delete"]
        assert TokenVerifier.has_scope("read", scope_claim) is True
        assert TokenVerifier.has_scope("admin", scope_claim) is False

    def test_has_scope_with_none_claim(self):
        """Test checking scope with None claim."""
        with pytest.raises(ScopeError):
            TokenVerifier.has_scope("read", None)

    def test_has_scope_with_invalid_claim_type(self):
        """Test checking scope with invalid claim type."""
        with pytest.raises(ScopeError):
            TokenVerifier.has_scope("read", 123)

    def test_has_scope_missing_required_scope(self):
        """Test checking scope when required scope is missing."""
        scope_claim = "read write"
        with pytest.raises(ScopeError) as exc_info:
            TokenVerifier.has_scope("admin", scope_claim)

        assert exc_info.value.required_scope == "admin"
        assert "read" in exc_info.value.available_scopes


class TestJWKSCaching:
    """Tests for JWKS caching."""

    def test_jwks_caching(self, mock_jwks_response):
        """Test that JWKS is cached and reused."""
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "https://auth.example.com/.well-known/jwks.json",
                json=mock_jwks_response["jwks"],
                status=200,
            )

            verifier = TokenVerifier(
                authority="https://auth.example.com",
                audience="my-api",
                validation_mode="jwt_signature",
            )

            token = jwt.encode(
                {
                    "iss": "https://auth.example.com",
                    "aud": "my-api",
                    "sub": "user123",
                    "exp": int(time.time()) + 3600,
                },
                mock_jwks_response["private_key"],
                algorithm="RS256",
                headers={"kid": "test-key-id"},
            )

            verifier.verify(token)
            assert len(rsps.calls) == 1

            verifier.verify(token)
            assert len(rsps.calls) == 1

    def test_jwks_refresh_on_key_not_found(self):
        """Test JWKS refresh when key is not found."""
        jwks_v1 = {"keys": [{"kty": "RSA", "kid": "key-1", "n": "abc", "e": "AQAB"}]}
        jwks_v2 = {
            "keys": [
                {"kty": "RSA", "kid": "key-2", "n": "def", "e": "AQAB"},
            ]
        }

        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "https://auth.example.com/.well-known/jwks.json",
                json=jwks_v1,
                status=200,
            )
            rsps.add(
                responses.GET,
                "https://auth.example.com/.well-known/jwks.json",
                json=jwks_v2,
                status=200,
            )

            verifier = TokenVerifier(
                authority="https://auth.example.com",
                audience="my-api",
                validation_mode="jwt_signature",
                jwks_cache_duration_hours=0,
            )

            assert len(rsps.calls) == 1


class TestIntrospection:
    """Tests for introspection mode."""

    def test_introspection_active_token(self):
        """Test introspecting an active token."""
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.POST,
                "https://auth.example.com/connect/introspect",
                json={
                    "active": True,
                    "scope": "read write",
                    "sub": "user123",
                    "client_id": "client-1",
                    "exp": int(time.time()) + 3600,
                },
                status=200,
            )

            verifier = TokenVerifier(
                authority="https://auth.example.com",
                audience="my-api",
                validation_mode="introspection",
                introspection_client_id="introspection-client",
                introspection_client_secret="introspection-secret",
            )

            claims = verifier.verify("dummy-token")

            assert claims["active"] is True
            assert claims["scope"] == "read write"
            assert claims["sub"] == "user123"

    def test_introspection_inactive_token(self):
        """Test introspecting an inactive token."""
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.POST,
                "https://auth.example.com/connect/introspect",
                json={"active": False},
                status=200,
            )

            verifier = TokenVerifier(
                authority="https://auth.example.com",
                audience="my-api",
                validation_mode="introspection",
                introspection_client_id="introspection-client",
                introspection_client_secret="introspection-secret",
            )

            with pytest.raises(TokenValidationError):
                verifier.verify("dummy-token")

    def test_introspection_cache(self):
        """Test that introspection results are cached."""
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.POST,
                "https://auth.example.com/connect/introspect",
                json={
                    "active": True,
                    "scope": "read write",
                    "sub": "user123",
                },
                status=200,
            )

            verifier = TokenVerifier(
                authority="https://auth.example.com",
                audience="my-api",
                validation_mode="introspection",
                introspection_client_id="introspection-client",
                introspection_client_secret="introspection-secret",
                introspection_cache_ttl_seconds=60,
            )

            verifier.verify("token1")
            assert len(rsps.calls) == 1

            verifier.verify("token1")
            assert len(rsps.calls) == 1

            verifier.verify("token2")
            assert len(rsps.calls) == 2


class TestClockSkew:
    """Tests for clock skew tolerance."""

    @freezegun.freeze_time("2024-01-01 12:00:00")
    def test_clock_skew_acceptance(self, token_verifier, valid_token):
        """Test that tokens with slight clock skew are accepted."""
        with freezegun.freeze_time("2024-01-01 12:05:00"):
            token = valid_token(exp=int(time.time()) + 100)

            claims = token_verifier.verify(token)
            assert claims["sub"] == "user123"

    @freezegun.freeze_time("2024-01-01 12:00:00")
    def test_clock_skew_rejection(self, token_verifier, valid_token):
        """Test that tokens beyond clock skew tolerance are rejected."""
        with freezegun.freeze_time("2024-01-01 12:10:00"):
            token = valid_token(exp=int(time.time()) - 100)

            with pytest.raises(TokenExpiredError):
                token_verifier.verify(token)

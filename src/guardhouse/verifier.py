"""Token verifier with JWKS caching and JWT validation."""

import hashlib
import json
import threading
import time
from typing import Any

import httpx
import jwt
from jwt import PyJWKClient, PyJWKClientError
from jwt.utils import base64url_decode

from guardhouse.config import IntrospectionResponse
from guardhouse.constants import (
    Algorithms,
    Defaults,
    Endpoints,
    Headers,
    IntrospectionCredentialTransmission,
)
from guardhouse.exceptions import (
    GuardhouseConfigError,
    GuardhouseNetworkError,
    InvalidAlgorithmError,
    JWKSFetchError,
    ScopeError,
    TokenExpiredError,
    TokenValidationError,
)


class _IntrospectionCache:
    """TTL cache for introspection results."""

    def __init__(self, ttl_seconds: int = Defaults.INTROSPECTION_CACHE_TTL_SECONDS) -> None:
        self._cache: dict[str, tuple[bool, float]] = {}
        self._ttl = ttl_seconds
        self._lock = threading.RLock()

    def get(self, key: str) -> bool | None:
        """Get cached result if it exists and is not expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            is_active, expires_at = entry
            if time.time() >= expires_at:
                del self._cache[key]
                return None
            return is_active

    def set(self, key: str, is_active: bool) -> None:
        """Set cached result with TTL."""
        with self._lock:
            self._cache[key] = (is_active, time.time() + self._ttl)

    def invalidate(self, key: str) -> None:
        """Invalidate cached result."""
        with self._lock:
            self._cache.pop(key, None)


class TokenVerifier:
    """Token verifier with JWKS caching and strict validation.

    Supports two validation modes:
    1. JWT Signature Validation (default): Validates token signature using JWKS
    2. Introspection: Validates token by calling introspection endpoint

    Security Features:
    ------------------
    - Strict algorithm enforcement (RS256 only, no "none")
    - Issuer validation
    - Audience validation
    - Expiration validation with clock skew tolerance
    - JWKS caching with automatic refresh
    - Introspection micro-caching (5 seconds default)
    - Scope validation
    - Token type validation ("JWT")

    Usage:
    -------
    >>> verifier = TokenVerifier(
    ...     authority="https://auth.example.com",
    ...     audience="my-api"
    ... )
    >>> claims = verifier.verify("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
    >>> has_read_scope = verifier.has_scope("read", claims.get("scope", ""))
    """

    def __init__(
        self,
        authority: str,
        audience: str,
        validation_mode: str = "jwt_signature",
        introspection_client_id: str | None = None,
        introspection_client_secret: str | None = None,
        introspection_credential_transmission: str = IntrospectionCredentialTransmission.BASIC_AUTH,
        jwks_cache_duration_hours: int = Defaults.JWKS_CACHE_DURATION_HOURS,
        jwks_refresh_interval_minutes: int = Defaults.JWKS_REFRESH_INTERVAL_MINUTES,
        introspection_cache_ttl_seconds: int = Defaults.INTROSPECTION_CACHE_TTL_SECONDS,
        validate_issuer: bool = True,
        validate_audience: bool = True,
        validate_lifetime: bool = True,
        clock_skew_minutes: float = Defaults.CLOCK_SKEW_MINUTES,
        valid_algorithms: list[str] | None = None,
    ) -> None:
        """Initialize TokenVerifier.

        Args:
            authority: Identity server URL
            audience: Expected audience in tokens
            validation_mode: "jwt_signature" or "introspection"
            introspection_client_id: Client ID for introspection (required for introspection mode)
            introspection_client_secret: Client secret for introspection (required for introspection mode)
            introspection_credential_transmission: Method for transmitting introspection credentials
            jwks_cache_duration_hours: JWKS cache duration in hours
            jwks_refresh_interval_minutes: Minimum interval between JWKS refreshes
            introspection_cache_ttl_seconds: Introspection cache TTL in seconds
            validate_issuer: Validate issuer claim
            validate_audience: Validate audience claim
            validate_lifetime: Validate token lifetime
            clock_skew_minutes: Clock skew tolerance in minutes
            valid_algorithms: Valid JWT algorithms (default: ["RS256"])
        """
        from guardhouse.constants import SecurityDefaults

        if not any(authority.startswith(proto) for proto in SecurityDefaults.ALLOWED_URL_PROTOCOLS):
            raise GuardhouseConfigError(
                f"Authority must start with http:// or https://, got: {authority}",
                field="authority",
            )

        if len(authority) > SecurityDefaults.MAX_AUTHORITY_LENGTH:
            raise GuardhouseConfigError(
                f"Authority URL too long (max {SecurityDefaults.MAX_AUTHORITY_LENGTH} characters)",
                field="authority",
            )

        self.authority = authority.rstrip("/")
        self.audience = audience
        self.validation_mode = validation_mode
        self.introspection_client_id = introspection_client_id
        self.introspection_client_secret = introspection_client_secret
        self.introspection_credential_transmission = introspection_credential_transmission

        self.jwks_cache_duration_hours = jwks_cache_duration_hours
        self.jwks_refresh_interval_minutes = jwks_refresh_interval_minutes
        self.introspection_cache_ttl_seconds = introspection_cache_ttl_seconds
        self.validate_issuer = validate_issuer
        self.validate_audience = validate_audience
        self.validate_lifetime = validate_lifetime
        self.clock_skew_minutes = clock_skew_minutes
        self.valid_algorithms = valid_algorithms or ["RS256"]

        self._http_client: httpx.Client | None = None
        self._async_http_client: httpx.AsyncClient | None = None

        self._jwks_url = f"{self.authority}/{Endpoints.WELL_KNOWN_JWKS}"
        self._introspection_url = f"{self.authority}/{Endpoints.CONNECT_INTROSPECT}"

        self._jwks_client: PyJWKClient | None = None
        self._jwks_last_refresh: float = 0
        self._jwks_lock = threading.RLock()

        self._introspection_cache = _IntrospectionCache(self.introspection_cache_ttl_seconds)

        if self.validation_mode == "jwt_signature":
            self._init_jwks_client()
        else:
            self._validate_introspection_config()

    @property
    def _sync_client(self) -> httpx.Client:
        """Lazy-initialize sync HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.Client(timeout=Defaults.REQUEST_TIMEOUT_SECONDS, verify=True)
        return self._http_client

    @property
    def _async_client(self) -> httpx.AsyncClient:
        """Lazy-initialize async HTTP client."""
        if self._async_http_client is None:
            self._async_http_client = httpx.AsyncClient(
                timeout=Defaults.REQUEST_TIMEOUT_SECONDS, verify=True
            )
        return self._async_http_client

    def _init_jwks_client(self) -> None:
        """Initialize JWKS client."""
        try:
            self._jwks_client = PyJWKClient(self._jwks_url)
        except Exception as e:
            raise JWKSFetchError(
                f"Failed to initialize JWKS client: {e!s}", url=self._jwks_url
            ) from e

    def _validate_introspection_config(self) -> None:
        """Validate introspection configuration."""
        if not self.introspection_client_id or not self.introspection_client_secret:
            raise GuardhouseConfigError(
                "introspection_client_id and introspection_client_secret are required for introspection mode",
                field="introspection_client_id",
            )

    def _should_refresh_jwks(self) -> bool:
        """Check if JWKS should be refreshed."""
        if not self._jwks_client:
            return False
        refresh_interval = self.jwks_refresh_interval_minutes * 60
        return (time.time() - self._jwks_last_refresh) > refresh_interval

    def _refresh_jwks(self) -> None:
        """Refresh JWKS if needed (thread-safe)."""
        if not self._should_refresh_jwks():
            return

        with self._jwks_lock:
            if not self._should_refresh_jwks():
                return

            try:
                self._init_jwks_client()
                self._jwks_last_refresh = time.time()
            except Exception:
                pass

    def _get_token_preview(self, token: str, max_length: int = 20) -> str:
        """Get safe preview of token for logging."""
        if len(token) <= max_length:
            return token
        return token[:max_length] + "..."

    def _extract_header(self, token: str) -> dict[str, Any]:
        """Extract JWT header without validation."""
        try:
            header_b64 = token.split(".")[0]
            padding = len(header_b64) % 4
            if padding:
                header_b64 += "=" * (4 - padding)
            header_json = base64url_decode(header_b64)
            return json.loads(header_json)
        except (IndexError, ValueError, json.JSONDecodeError) as e:
            raise TokenValidationError(
                f"Invalid JWT format: {e!s}", token_preview=self._get_token_preview(token)
            ) from e

    def _validate_header(self, header: dict[str, Any]) -> None:
        """Validate JWT header for security."""
        alg = header.get("alg")
        if alg == Algorithms.NONE:
            raise InvalidAlgorithmError(
                'The "none" algorithm is not allowed for security reasons', algorithm=alg
            )

        if alg not in self.valid_algorithms:
            raise InvalidAlgorithmError(
                f"Invalid algorithm: {alg}. Expected one of: {', '.join(self.valid_algorithms)}",
                algorithm=alg,
            )

        token_type = header.get("typ")
        if token_type and token_type not in ["JWT"]:
            raise TokenValidationError(
                f"Invalid token type: {token_type}. Expected 'JWT'",
                token_preview=self._get_token_preview(header.get("kid", "")),
            )

    def _decode_jwt(self, token: str) -> dict[str, Any]:
        """Decode and validate JWT."""
        self._validate_header(self._extract_header(token))
        self._refresh_jwks()

        if self._jwks_client is None:
            raise TokenValidationError("JWKS client not initialized")

        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token).key

            decoded = jwt.decode(
                token,
                signing_key,
                algorithms=self.valid_algorithms,
                options={
                    "verify_iss": self.validate_issuer,
                    "verify_aud": self.validate_audience,
                    "verify_exp": self.validate_lifetime,
                    "require": ["iss", "exp", "aud"],
                },
                issuer=self.authority,
                audience=self.audience,
            )
            return decoded
        except jwt.ExpiredSignatureError as e:
            raise TokenExpiredError("Token has expired") from e
        except jwt.InvalidIssuerError as e:
            raise TokenValidationError(f"Invalid issuer: {e!s}") from e
        except jwt.InvalidAudienceError as e:
            raise TokenValidationError(f"Invalid audience: {e!s}") from e
        except jwt.InvalidSignatureError as e:
            raise TokenValidationError("Invalid token signature") from e
        except jwt.InvalidKeyError as e:
            raise TokenValidationError(f"Invalid signing key: {e!s}") from e
        except PyJWKClientError as e:
            raise JWKSFetchError(f"Failed to fetch JWKS: {e!s}", url=self._jwks_url) from e
        except Exception as e:
            raise TokenValidationError(f"Token validation failed: {e!s}") from e

    def _get_introspection_cache_key(self, token: str) -> str:
        """Get cache key for introspection."""
        return f"introspection:{hashlib.sha256(token.encode()).hexdigest()}"

    def _introspect_token(self, token: str) -> IntrospectionResponse:
        """Introspect token (sync)."""
        cache_key = self._get_introspection_cache_key(token)
        cached = self._introspection_cache.get(cache_key)

        if cached is not None:
            if not cached:
                raise TokenValidationError("Token is not active")
            return IntrospectionResponse(active=True)

        headers: dict[str, str] = {Headers.CONTENT_TYPE: Headers.APPLICATION_URLENCODED}
        data: dict[str, str] = {"token": token}

        if (
            self.introspection_credential_transmission
            == IntrospectionCredentialTransmission.BASIC_AUTH
        ):
            import base64

            credentials = f"{self.introspection_client_id}:{self.introspection_client_secret}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers[Headers.AUTHORIZATION] = f"Basic {encoded}"
        else:
            data["client_id"] = str(self.introspection_client_id)
            data["client_secret"] = str(self.introspection_client_secret)

        try:
            response = self._sync_client.post(self._introspection_url, headers=headers, data=data)
            response.raise_for_status()
            result = IntrospectionResponse(**response.json())

            if not result.active:
                self._introspection_cache.set(cache_key, False)
                raise TokenValidationError("Token is not active")

            self._introspection_cache.set(cache_key, True)
            return result
        except httpx.HTTPStatusError as e:
            raise GuardhouseNetworkError(
                f"Introspection request failed: {e!s}",
                status_code=e.response.status_code,
                url=str(e.response.url),
            ) from e
        except Exception as e:
            raise GuardhouseNetworkError(f"Introspection failed: {e!s}") from e

    async def _introspect_token_async(self, token: str) -> IntrospectionResponse:
        """Introspect token (async)."""
        cache_key = self._get_introspection_cache_key(token)
        cached = self._introspection_cache.get(cache_key)

        if cached is not None:
            if not cached:
                raise TokenValidationError("Token is not active")
            return IntrospectionResponse(active=True)

        headers: dict[str, str] = {Headers.CONTENT_TYPE: Headers.APPLICATION_URLENCODED}
        data: dict[str, str] = {"token": token}

        if (
            self.introspection_credential_transmission
            == IntrospectionCredentialTransmission.BASIC_AUTH
        ):
            import base64

            credentials = f"{self.introspection_client_id}:{self.introspection_client_secret}"
            encoded = base64.b64encode(credentials.encode()).decode()
            headers[Headers.AUTHORIZATION] = f"Basic {encoded}"
        else:
            data["client_id"] = str(self.introspection_client_id)
            data["client_secret"] = str(self.introspection_client_secret)

        try:
            response = await self._async_client.post(
                self._introspection_url, headers=headers, data=data
            )
            response.raise_for_status()
            result = IntrospectionResponse(**response.json())

            if not result.active:
                self._introspection_cache.set(cache_key, False)
                raise TokenValidationError("Token is not active")

            self._introspection_cache.set(cache_key, True)
            return result
        except httpx.HTTPStatusError as e:
            raise GuardhouseNetworkError(
                f"Introspection request failed: {e!s}",
                status_code=e.response.status_code,
                url=str(e.response.url),
            ) from e
        except Exception as e:
            raise GuardhouseNetworkError(f"Introspection failed: {e!s}") from e

    def verify(self, token: str) -> dict[str, Any]:
        """Verify token and return claims (sync).

        Args:
            token: JWT token string

        Returns:
            Dictionary of token claims

        Raises:
            TokenValidationError: If token is invalid
            TokenExpiredError: If token is expired
            InvalidAlgorithmError: If token uses invalid algorithm
            JWKSFetchError: If JWKS fetch fails
            GuardhouseNetworkError: If network request fails
        """
        from guardhouse.constants import SecurityDefaults

        if not token:
            raise TokenValidationError("Token cannot be empty")

        if len(token) > SecurityDefaults.MAX_TOKEN_LENGTH:
            raise TokenValidationError(
                f"Token too long (max {SecurityDefaults.MAX_TOKEN_LENGTH} characters)"
            )

        if self.validation_mode == "jwt_signature":
            return self._decode_jwt(token)
        else:
            result = self._introspect_token(token)
            return {
                "active": result.active,
                "scope": result.scope,
                "client_id": result.client_id,
                "sub": result.sub,
                "aud": result.aud,
                "iss": result.iss,
                "exp": result.exp,
                "iat": result.iat,
            }

    async def verify_async(self, token: str) -> dict[str, Any]:
        """Verify token and return claims (async).

        Args:
            token: JWT token string

        Returns:
            Dictionary of token claims

        Raises:
            TokenValidationError: If token is invalid
            TokenExpiredError: If token is expired
            InvalidAlgorithmError: If token uses invalid algorithm
            JWKSFetchError: If JWKS fetch fails
            GuardhouseNetworkError: If network request fails
        """
        from guardhouse.constants import SecurityDefaults

        if not token:
            raise TokenValidationError("Token cannot be empty")

        if len(token) > SecurityDefaults.MAX_TOKEN_LENGTH:
            raise TokenValidationError(
                f"Token too long (max {SecurityDefaults.MAX_TOKEN_LENGTH} characters)"
            )

        if self.validation_mode == "jwt_signature":
            return self._decode_jwt(token)
        else:
            result = await self._introspect_token_async(token)
            return {
                "active": result.active,
                "scope": result.scope,
                "client_id": result.client_id,
                "sub": result.sub,
                "aud": result.aud,
                "iss": result.iss,
                "exp": result.exp,
                "iat": result.iat,
            }

    @staticmethod
    def has_scope(required_scope: str, scope_claim: str | list[str] | None) -> bool:
        """Check if token has required scope.

        Args:
            required_scope: Scope to check for (e.g., "read:users")
            scope_claim: Scope claim from token (string or list)

        Returns:
            True if token has the required scope, False otherwise

        Raises:
            ScopeError: If scope_claim is invalid
        """
        if scope_claim is None:
            raise ScopeError(
                "Token does not have a scope claim",
                required_scope=required_scope,
                available_scopes=[],
            )

        if isinstance(scope_claim, str):
            available_scopes = scope_claim.split()
        elif isinstance(scope_claim, list):
            available_scopes = scope_claim
        else:
            raise ScopeError(
                f"Invalid scope claim type: {type(scope_claim).__name__}",
                required_scope=required_scope,
                available_scopes=[],
            )

        if required_scope not in available_scopes:
            raise ScopeError(
                f"Token does not have required scope: {required_scope}",
                required_scope=required_scope,
                available_scopes=available_scopes,
            )

        return True

    def close(self) -> None:
        """Close the HTTP client (sync)."""
        if self._http_client is not None:
            self._http_client.close()

    async def close_async(self) -> None:
        """Close the async HTTP client."""
        if self._async_http_client is not None:
            await self._async_http_client.aclose()

    def __enter__(self) -> "TokenVerifier":
        """Context manager support (sync)."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager support (sync)."""
        self.close()

    async def __aenter__(self) -> "TokenVerifier":
        """Context manager support (async)."""
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Context manager support (async)."""
        await self.close_async()

    def __del__(self) -> None:
        """Cleanup on deletion."""
        if hasattr(self, "_http_client"):
            try:
                self.close()
            except Exception:
                pass

    def __repr__(self) -> str:
        """Safe repr."""
        return (
            f"TokenVerifier(authority={self.authority!r}, "
            f"audience={self.audience!r}, validation_mode={self.validation_mode!r})"
        )

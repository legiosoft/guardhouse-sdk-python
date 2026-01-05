"""Configuration models using Pydantic."""

from datetime import timedelta
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from guardhouse.constants import Defaults, GrantTypes
from guardhouse.exceptions import GuardhouseConfigError


class IntrospectionCredentialTransmission:
    """Transmission method for introspection credentials."""

    BASIC_AUTH = "basic_auth"
    POST_BODY = "post_body"


class GuardhouseClientOptions(BaseModel):
    """Configuration options for Guardhouse Client (M2M)."""

    authority: str = Field(..., description="Identity server URL")
    client_id: str = Field(..., description="Client ID")
    client_secret: str = Field(..., description="Client secret")
    scope: str = Field(default=Defaults.DEFAULT_SCOPE, description="Requested scope")

    enable_token_caching: bool = Field(default=True, description="Enable token caching")
    cache_expiration_buffer_seconds: int = Field(
        default=Defaults.CACHE_EXPIRATION_BUFFER_SECONDS,
        ge=0,
        description="Buffer in seconds before token expiration to refresh",
    )

    enable_token_refresh: bool = Field(default=True, description="Enable automatic token refresh")

    request_timeout_seconds: int = Field(
        default=Defaults.REQUEST_TIMEOUT_SECONDS,
        ge=1,
        description="HTTP request timeout in seconds",
    )
    max_retry_attempts: int = Field(
        default=Defaults.MAX_RETRY_ATTEMPTS,
        ge=0,
        description="Maximum number of retry attempts",
    )
    enable_http_resilience: bool = Field(
        default=True, description="Enable HTTP resilience with retries"
    )

    introspection_client_id: str | None = Field(
        default=None, description="Optional: Client ID for introspection endpoint"
    )
    introspection_client_secret: str | None = Field(
        default=None, description="Optional: Client secret for introspection endpoint"
    )
    introspection_credential_transmission: Literal["basic_auth", "post_body"] = Field(
        default="basic_auth", description="Method for transmitting introspection credentials"
    )

    @field_validator("authority")
    @classmethod
    def validate_authority(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise GuardhouseConfigError(
                f"Authority must start with http:// or https://, got: {v}", field="authority"
            )
        return v.rstrip("/")

    @model_validator(mode="after")
    def validate_introspection_credentials(self) -> "GuardhouseClientOptions":
        if self.introspection_client_id and not self.introspection_client_secret:
            raise GuardhouseConfigError(
                "introspection_client_secret is required when introspection_client_id is provided",
                field="introspection_client_secret",
            )
        if self.introspection_client_secret and not self.introspection_client_id:
            raise GuardhouseConfigError(
                "introspection_client_id is required when introspection_client_secret is provided",
                field="introspection_client_id",
            )
        return self


class TokenResponse(BaseModel):
    """Response from token endpoint."""

    access_token: str
    token_type: str = Defaults.DEFAULT_TOKEN_TYPE
    expires_in: int
    refresh_token: str | None = None
    scope: str | None = None
    error: str | None = None
    error_description: str | None = None

    def is_expired(self, buffer_seconds: int = 0) -> bool:
        """Check if token is expired considering buffer."""
        from time import time

        return time() >= (self.expires_at - buffer_seconds)

    @property
    def expires_at(self) -> float:
        """Get expiration timestamp."""
        from time import time

        return time() + self.expires_in


class IntrospectionResponse(BaseModel):
    """Response from introspection endpoint."""

    active: bool
    scope: str | None = None
    client_id: str | None = None
    username: str | None = None
    token_type: str | None = None
    exp: int | None = None
    iat: int | None = None
    nbf: int | None = None
    sub: str | None = None
    aud: str | list[str] | None = None
    iss: str | None = None
    jti: str | None = None


class GuardhouseResourceOptions(BaseModel):
    """Configuration options for Guardhouse Resource Server."""

    authority: str = Field(..., description="Identity server URL")
    audience: str = Field(..., description="Expected audience in tokens")

    validation_mode: Literal["jwt_signature", "introspection"] = Field(
        default="jwt_signature", description="Token validation mode"
    )

    introspection_client_id: str | None = Field(
        default=None, description="Client ID for introspection (required for introspection mode)"
    )
    introspection_client_secret: str | None = Field(
        default=None,
        description="Client secret for introspection (required for introspection mode)",
    )
    introspection_credential_transmission: Literal["basic_auth", "post_body"] = Field(
        default="basic_auth", description="Method for transmitting introspection credentials"
    )

    policy_name: str = Field(default="Guardhouse", description="Authentication policy name")

    validate_issuer: bool = Field(default=True, description="Validate issuer claim")
    validate_audience: bool = Field(default=True, description="Validate audience claim")
    validate_lifetime: bool = Field(default=True, description="Validate token lifetime")
    validate_issuer_signing_key: bool = Field(default=True, description="Validate signing key")

    jwks_cache_duration_hours: int = Field(
        default=Defaults.JWKS_CACHE_DURATION_HOURS,
        ge=1,
        description="JWKS cache duration in hours",
    )
    jwks_refresh_interval_minutes: int = Field(
        default=Defaults.JWKS_REFRESH_INTERVAL_MINUTES,
        ge=1,
        description="Minimum interval between JWKS refreshes in minutes",
    )

    introspection_cache_ttl_seconds: int = Field(
        default=Defaults.INTROSPECTION_CACHE_TTL_SECONDS,
        ge=0,
        description="Introspection cache TTL in seconds",
    )

    valid_algorithms: list[str] = Field(
        default_factory=lambda: ["RS256"], description="Valid JWT algorithms"
    )
    token_types: list[str] = Field(default_factory=lambda: ["JWT"], description="Valid token types")

    clock_skew_minutes: float = Field(
        default=Defaults.CLOCK_SKEW_MINUTES, ge=0, description="Clock skew tolerance in minutes"
    )

    @field_validator("authority")
    @classmethod
    def validate_authority(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise GuardhouseConfigError(
                f"Authority must start with http:// or https://, got: {v}", field="authority"
            )
        return v.rstrip("/")

    @model_validator(mode="after")
    def validate_introspection_credentials(self) -> "GuardhouseResourceOptions":
        if self.validation_mode == "introspection":
            if not self.introspection_client_id:
                raise GuardhouseConfigError(
                    "introspection_client_id is required when validation_mode is 'introspection'",
                    field="introspection_client_id",
                )
            if not self.introspection_client_secret:
                raise GuardhouseConfigError(
                    "introspection_client_secret is required when validation_mode is 'introspection'",
                    field="introspection_client_secret",
                )
        return self

    @property
    def clock_skew_seconds(self) -> int:
        """Get clock skew tolerance in seconds."""
        return int(self.clock_skew_minutes * 60)


class JWKSResponse(BaseModel):
    """Response from JWKS endpoint."""

    keys: list[dict]


class JWKKey(BaseModel):
    """JSON Web Key representation."""

    kty: str
    use: str | None = None
    key_ops: list[str] | None = None
    alg: str | None = None
    kid: str | None = None
    n: str | None = None
    e: str | None = None
    x: str | None = None
    y: str | None = None
    crv: str | None = None

    def to_pem(self) -> str:
        """Convert JWK to PEM format."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization

        if self.kty == "RSA" and self.n and self.e:
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

            n = int.from_bytes(self._base64url_decode(self.n), byteorder="big")
            e = int.from_bytes(self._base64url_decode(self.e), byteorder="big")
            public_key = RSAPublicNumbers(e, n).public_key()
            return (
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode("utf-8")
                .strip()
            )
        raise ValueError(f"Unsupported key type: {self.kty}")

    @staticmethod
    def _base64url_decode(data: str) -> bytes:
        """Decode Base64URL encoded data."""
        import base64

        padding = len(data) % 4
        if padding:
            data += "=" * (4 - padding)
        return base64.urlsafe_b64decode(data)

"""Constants module for Guardhouse SDK."""


class Endpoints:
    """OAuth 2.0 and OpenID Connect endpoints."""

    WELL_KNOWN_OPENID_CONFIGURATION = ".well-known/openid-configuration"
    WELL_KNOWN_JWKS = ".well-known/jwks.json"
    CONNECT_TOKEN = "connect/token"
    CONNECT_INTROSPECT = "connect/introspect"
    CONNECT_AUTHORIZE = "connect/authorize"


class Algorithms:
    """JWT algorithms."""

    RS256 = "RS256"
    NONE = "none"


class Headers:
    """HTTP headers."""

    AUTHORIZATION = "Authorization"
    BEARER_PREFIX = "Bearer "
    CONTENT_TYPE = "Content-Type"
    APPLICATION_JSON = "application/json"
    APPLICATION_URLENCODED = "application/x-www-form-urlencoded"


class Defaults:
    """Default configuration values."""

    JWKS_CACHE_DURATION_HOURS = 24
    JWKS_REFRESH_INTERVAL_MINUTES = 5
    CACHE_EXPIRATION_BUFFER_SECONDS = 60
    REQUEST_TIMEOUT_SECONDS = 30
    MAX_RETRY_ATTEMPTS = 3
    CLOCK_SKEW_MINUTES = 5.0
    DEFAULT_SCOPE = "api"
    INTROSPECTION_CACHE_TTL_SECONDS = 5
    DEFAULT_TOKEN_TYPE = "Bearer"


class GrantTypes:
    """OAuth 2.0 grant types."""

    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"


class TokenErrors:
    """Token error types."""

    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    INVALID_SCOPE = "invalid_scope"


class Claims:
    """JWT claim types."""

    ISSUER = "iss"
    AUDIENCE = "aud"
    EXPIRATION = "exp"
    ISSUED_AT = "iat"
    NOT_BEFORE = "nbf"
    SUBJECT = "sub"
    SCOPE = "scope"
    KEY_ID = "kid"
    ALGORITHM = "alg"
    TYPE = "typ"


class CacheKeys:
    """Cache key prefixes."""

    ACCESS_TOKEN = "access_token"
    JWKS = "jwks"
    INTROSPECTION = "introspection"


class IntrospectionCredentialTransmission:
    """Transmission method for introspection credentials."""

    BASIC_AUTH = "basic_auth"
    POST_BODY = "post_body"


class SecurityDefaults:
    """Security-related default values."""

    ALLOWED_URL_PROTOCOLS = ["http://", "https://"]
    MAX_AUTHORITY_LENGTH = 255
    MAX_TOKEN_LENGTH = 8192

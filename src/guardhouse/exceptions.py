"""Custom exceptions for Guardhouse SDK."""


class GuardhouseError(Exception):
    """Base exception for all Guardhouse SDK errors."""


class GuardhouseConfigError(GuardhouseError):
    """Raised when configuration is invalid or missing."""

    def __init__(self, message: str, field: str | None = None) -> None:
        self.field = field
        super().__init__(message)


class TokenValidationError(GuardhouseError):
    """Raised when token validation fails."""

    def __init__(self, message: str, token_preview: str | None = None) -> None:
        self.token_preview = token_preview
        super().__init__(message)


class ScopeError(GuardhouseError):
    """Raised when token doesn't have required scope."""

    def __init__(
        self, message: str, required_scope: str, available_scopes: list[str] | None = None
    ) -> None:
        self.required_scope = required_scope
        self.available_scopes = available_scopes or []
        super().__init__(message)


class GuardhouseAuthError(GuardhouseError):
    """Raised when authentication fails."""

    def __init__(
        self, message: str, error_code: str | None = None, error_description: str | None = None
    ) -> None:
        self.error_code = error_code
        self.error_description = error_description
        super().__init__(message)


class GuardhouseNetworkError(GuardhouseError):
    """Raised when network request fails."""

    def __init__(
        self, message: str, status_code: int | None = None, url: str | None = None
    ) -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(message)


class TokenRefreshError(GuardhouseError):
    """Raised when token refresh fails."""

    pass


class JWKSFetchError(GuardhouseError):
    """Raised when JWKS fetch fails."""

    def __init__(self, message: str, url: str | None = None) -> None:
        self.url = url
        super().__init__(message)


class TokenExpiredError(TokenValidationError):
    """Raised when token is expired."""

    pass


class InvalidAlgorithmError(TokenValidationError):
    """Raised when token uses invalid algorithm."""

    def __init__(self, message: str, algorithm: str | None = None) -> None:
        self.algorithm = algorithm
        super().__init__(message)

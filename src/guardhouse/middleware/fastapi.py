"""FastAPI middleware integration for Guardhouse."""

from functools import lru_cache
from typing import Any, Callable

from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel

from guardhouse.constants import Headers
from guardhouse.exceptions import (
    InvalidAlgorithmError,
    JWKSFetchError,
    ScopeError,
    TokenExpiredError,
    TokenValidationError,
)
from guardhouse.verifier import TokenVerifier


class User(BaseModel):
    """User information extracted from token."""

    sub: str
    scope: str | None = None
    client_id: str | None = None
    iss: str | None = None
    aud: str | list[str] | None = None
    exp: int | None = None
    iat: int | None = None

    def has_scope(self, required_scope: str) -> bool:
        """Check if user has required scope.

        Args:
            required_scope: Scope to check for

        Returns:
            True if user has the required scope, False otherwise
        """
        if not self.scope:
            return False
        available_scopes = self.scope.split()
        return required_scope in available_scopes


@lru_cache
def _get_verifier(
    authority: str,
    audience: str,
    validation_mode: str = "jwt_signature",
    **kwargs: Any,
) -> TokenVerifier:
    """Get or create cached TokenVerifier instance.

    This allows the verifier to be reused across multiple requests,
    maintaining JWKS cache and connection pooling.

    Args:
        authority: Identity server URL
        audience: Expected audience in tokens
        validation_mode: "jwt_signature" or "introspection"
        **kwargs: Additional options for TokenVerifier

    Returns:
        TokenVerifier instance
    """
    return TokenVerifier(
        authority=authority,
        audience=audience,
        validation_mode=validation_mode,
        **kwargs,
    )


def _extract_token_from_request(request: Request) -> str:
    """Extract bearer token from request headers.

    Args:
        request: FastAPI Request object

    Returns:
        Token string

    Raises:
        HTTPException: If token is missing or invalid
    """
    from guardhouse.constants import SecurityDefaults

    authorization = request.headers.get(Headers.AUTHORIZATION)

    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not authorization.startswith(Headers.BEARER_PREFIX):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[len(Headers.BEARER_PREFIX) :]
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is empty",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if len(token) > SecurityDefaults.MAX_TOKEN_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Token too long (max {SecurityDefaults.MAX_TOKEN_LENGTH} characters)",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token


def requires_auth(
    authority: str,
    audience: str,
    validation_mode: str = "jwt_signature",
    **kwargs: Any,
) -> Callable[[Request], User]:
    """Create dependency function for token verification.

    Usage:
    -------
    >>> from fastapi import FastAPI, Depends
    >>> from guardhouse.middleware.fastapi import requires_auth, User
    >>>
    >>> app = FastAPI()
    >>> get_user = requires_auth(
    ...     authority="https://auth.example.com",
    ...     audience="my-api"
    ... )
    >>>
    >>> @app.get("/protected")
    >>> async def protected_route(user: User = Depends(get_user)):
    ...     return {"message": f"Hello, {user.sub}!"}
    >>>
    >>> @app.get("/admin")
    >>> async def admin_route(
    ...     user: User = Depends(get_user)
    ... ):
    ...     if not user.has_scope("admin"):
    ...         raise HTTPException(status_code=403, detail="Admin scope required")
    ...     return {"message": "Welcome admin!"}

    Args:
        authority: Identity server URL
        audience: Expected audience in tokens
        validation_mode: "jwt_signature" or "introspection"
        **kwargs: Additional options for TokenVerifier

    Returns:
        Dependency function that returns User object

    Raises:
        HTTPException: If token is invalid, expired, or missing required scope
    """
    verifier = _get_verifier(
        authority=authority,
        audience=audience,
        validation_mode=validation_mode,
        **kwargs,
    )

    def _verify_token(request: Request) -> User:
        token = _extract_token_from_request(request)

        try:
            claims = verifier.verify(token)
        except TokenExpiredError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except InvalidAlgorithmError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token algorithm: {e.algorithm}",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except JWKSFetchError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to fetch JWKS. Please try again later.",
            )
        except TokenValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
                headers={"WWW-Authenticate": "Bearer"},
            )

        return User(
            sub=claims.get("sub", ""),
            scope=claims.get("scope"),
            client_id=claims.get("client_id"),
            iss=claims.get("iss"),
            aud=claims.get("aud"),
            exp=claims.get("exp"),
            iat=claims.get("iat"),
        )

    return _verify_token


def requires_scope(required_scope: str) -> Callable[[User], User]:
    """Create dependency function for scope checking.

    Usage:
    -------
    >>> from fastapi import Depends
    >>> from guardhouse.middleware.fastapi import requires_auth, requires_scope, User
    >>>
    >>> get_user = requires_auth(
    ...     authority="https://auth.example.com",
    ...     audience="my-api"
    ... )
    >>>
    >>> @app.get("/users")
    >>> async def get_users(
    ...     user: User = Depends(requires_scope("read:users")(get_user))
    ... ):
    ...     return {"users": []}

    Args:
        required_scope: Required scope (e.g., "read:users", "admin")

    Returns:
        Dependency function that returns User object if scope is present

    Raises:
        HTTPException: If token doesn't have the required scope
    """

    def _check_scope(user: User) -> User:
        if not user.has_scope(required_scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope: {required_scope}",
            )
        return user

    return _check_scope


async def requires_auth_async(
    authority: str,
    audience: str,
    validation_mode: str = "jwt_signature",
    **kwargs: Any,
) -> Callable[[Request], User]:
    """Create async dependency function for token verification.

    Usage:
    -------
    >>> from fastapi import FastAPI, Depends
    >>> from guardhouse.middleware.fastapi import requires_auth_async, User
    >>>
    >>> app = FastAPI()
    >>> get_user_async = requires_auth_async(
    ...     authority="https://auth.example.com",
    ...     audience="my-api"
    ... )
    >>>
    >>> @app.get("/protected")
    >>> async def protected_route(user: User = Depends(get_user_async)):
    ...     return {"message": f"Hello, {user.sub}!"}

    Args:
        authority: Identity server URL
        audience: Expected audience in tokens
        validation_mode: "jwt_signature" or "introspection"
        **kwargs: Additional options for TokenVerifier

    Returns:
        Async dependency function that returns User object

    Raises:
        HTTPException: If token is invalid, expired, or missing required scope
    """
    verifier = _get_verifier(
        authority=authority,
        audience=audience,
        validation_mode=validation_mode,
        **kwargs,
    )

    async def _verify_token(request: Request) -> User:
        token = _extract_token_from_request(request)

        try:
            claims = await verifier.verify_async(token)
        except TokenExpiredError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except InvalidAlgorithmError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token algorithm: {e.algorithm}",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except JWKSFetchError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Failed to fetch JWKS. Please try again later.",
            )
        except TokenValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
                headers={"WWW-Authenticate": "Bearer"},
            )

        return User(
            sub=claims.get("sub", ""),
            scope=claims.get("scope"),
            client_id=claims.get("client_id"),
            iss=claims.get("iss"),
            aud=claims.get("aud"),
            exp=claims.get("exp"),
            iat=claims.get("iat"),
        )

    return _verify_token

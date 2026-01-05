"""Flask middleware integration for Guardhouse."""

from functools import wraps
from typing import Any, Callable

from flask import abort, request

from guardhouse.constants import Headers
from guardhouse.exceptions import (
    InvalidAlgorithmError,
    JWKSFetchError,
    ScopeError,
    TokenExpiredError,
    TokenValidationError,
)
from guardhouse.verifier import TokenVerifier


class FlaskAuthExtension:
    """Flask extension for Guardhouse authentication.

    Usage:
    -------
    >>> from flask import Flask
    >>> from guardhouse.middleware.flask import FlaskAuthExtension
    >>>
    >>> app = Flask(__name__)
    >>> auth = FlaskAuthExtension(app)
    >>>
    >>> @app.route("/protected")
    >>> @auth.requires_auth
    >>> def protected():
    ...     return {"message": "Hello!"}
    """

    def __init__(
        self,
        app: Any | None = None,
        authority: str = "",
        audience: str = "",
        validation_mode: str = "jwt_signature",
        **kwargs: Any,
    ) -> None:
        """Initialize FlaskAuthExtension.

        Args:
            app: Flask application instance
            authority: Identity server URL
            audience: Expected audience in tokens
            validation_mode: "jwt_signature" or "introspection"
            **kwargs: Additional options for TokenVerifier
        """
        self.authority = authority
        self.audience = audience
        self.validation_mode = validation_mode
        self.verifier_kwargs = kwargs
        self._verifier: TokenVerifier | None = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Any) -> None:
        """Initialize extension with Flask app.

        Args:
            app: Flask application instance
        """
        app.config.setdefault("GUARDHOUSE_AUTHORITY", self.authority)
        app.config.setdefault("GUARDHOUSE_AUDIENCE", self.audience)
        app.config.setdefault("GUARDHOUSE_VALIDATION_MODE", self.validation_mode)

        self.authority = app.config["GUARDHOUSE_AUTHORITY"]
        self.audience = app.config["GUARDHOUSE_AUDIENCE"]
        self.validation_mode = app.config["GUARDHOUSE_VALIDATION_MODE"]

        self._verifier = TokenVerifier(
            authority=self.authority,
            audience=self.audience,
            validation_mode=self.validation_mode,
            **self.verifier_kwargs,
        )

    @property
    def verifier(self) -> TokenVerifier:
        """Get TokenVerifier instance."""
        if self._verifier is None:
            self._verifier = TokenVerifier(
                authority=self.authority,
                audience=self.audience,
                validation_mode=self.validation_mode,
                **self.verifier_kwargs,
            )
        return self._verifier

    def requires_auth(
        self,
        f: Callable[..., Any] | None = None,
        required_scope: str | None = None,
    ) -> Callable[..., Any]:
        """Decorator to require authentication.

        Usage:
        -------
        >>> @app.route("/protected")
        >>> @auth.requires_auth
        >>> def protected():
        ...     return {"message": "Hello!"}
        >>>
        >>> @app.route("/admin")
        >>> @auth.requires_auth(required_scope="admin")
        >>> def admin():
        ...     return {"message": "Welcome admin!"}

        Args:
            f: Function to decorate
            required_scope: Optional required scope

        Returns:
            Decorated function
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                token = self._extract_token_from_request()

                try:
                    claims = self.verifier.verify(token)
                except TokenExpiredError:
                    abort(401, description="Token has expired")
                except InvalidAlgorithmError as e:
                    abort(401, description=f"Invalid token algorithm: {e.algorithm}")
                except JWKSFetchError:
                    abort(503, description="Failed to fetch JWKS. Please try again later.")
                except TokenValidationError as e:
                    abort(401, description=str(e))

                if required_scope:
                    try:
                        TokenVerifier.has_scope(required_scope, claims.get("scope"))
                    except ScopeError:
                        abort(403, description=f"Missing required scope: {required_scope}")

                kwargs["user"] = {
                    "sub": claims.get("sub", ""),
                    "scope": claims.get("scope"),
                    "client_id": claims.get("client_id"),
                    "iss": claims.get("iss"),
                    "aud": claims.get("aud"),
                    "exp": claims.get("exp"),
                    "iat": claims.get("iat"),
                }

                return func(*args, **kwargs)

            return wrapper

        if f is not None:
            return decorator(f)
        return decorator

    def _extract_token_from_request(self) -> str:
        """Extract bearer token from request headers.

        Returns:
            Token string

        Raises:
            HTTP 401: If token is missing or invalid
        """
        from guardhouse.constants import SecurityDefaults

        authorization = request.headers.get(Headers.AUTHORIZATION)

        if not authorization:
            abort(401, description="Missing Authorization header")

        if not authorization.startswith(Headers.BEARER_PREFIX):
            abort(401, description="Invalid Authorization header format. Expected 'Bearer <token>'")

        token = authorization[len(Headers.BEARER_PREFIX) :]
        if not token:
            abort(401, description="Token is empty")

        if len(token) > SecurityDefaults.MAX_TOKEN_LENGTH:
            abort(
                413,
                description=f"Token too long (max {SecurityDefaults.MAX_TOKEN_LENGTH} characters)",
            )

        return token

    def requires_scope(
        self, required_scope: str
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator to require specific scope.

        Usage:
        -------
        >>> @app.route("/users")
        >>> @auth.requires_scope("read:users")
        >>> def get_users():
        ...     return {"users": []}

        Args:
            required_scope: Required scope

        Returns:
            Decorator function
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                token = self._extract_token_from_request()

                try:
                    claims = self.verifier.verify(token)
                except TokenExpiredError:
                    abort(401, description="Token has expired")
                except InvalidAlgorithmError as e:
                    abort(401, description=f"Invalid token algorithm: {e.algorithm}")
                except JWKSFetchError:
                    abort(503, description="Failed to fetch JWKS. Please try again later.")
                except TokenValidationError as e:
                    abort(401, description=str(e))

                try:
                    TokenVerifier.has_scope(required_scope, claims.get("scope"))
                except ScopeError:
                    abort(403, description=f"Missing required scope: {required_scope}")

                kwargs["user"] = {
                    "sub": claims.get("sub", ""),
                    "scope": claims.get("scope"),
                    "client_id": claims.get("client_id"),
                    "iss": claims.get("iss"),
                    "aud": claims.get("aud"),
                    "exp": claims.get("exp"),
                    "iat": claims.get("iat"),
                }

                return func(*args, **kwargs)

            return wrapper

        return decorator


def create_auth_decorator(
    authority: str,
    audience: str,
    validation_mode: str = "jwt_signature",
    **kwargs: Any,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Create a standalone auth decorator without Flask extension.

    Usage:
    -------
    >>> from flask import Flask
    >>> from guardhouse.middleware.flask import create_auth_decorator
    >>>
    >>> app = Flask(__name__)
    >>> requires_auth = create_auth_decorator(
    ...     authority="https://auth.example.com",
    ...     audience="my-api"
    ... )
    >>>
    >>> @app.route("/protected")
    >>> @requires_auth
    >>> def protected():
    ...     return {"message": "Hello!"}

    Args:
        authority: Identity server URL
        audience: Expected audience in tokens
        validation_mode: "jwt_signature" or "introspection"
        **kwargs: Additional options for TokenVerifier

    Returns:
        Decorator function
    """
    verifier = TokenVerifier(
        authority=authority,
        audience=audience,
        validation_mode=validation_mode,
        **kwargs,
    )

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            authorization = request.headers.get(Headers.AUTHORIZATION)

            if not authorization:
                abort(401, description="Missing Authorization header")

            if not authorization.startswith(Headers.BEARER_PREFIX):
                abort(
                    401,
                    description="Invalid Authorization header format. Expected 'Bearer <token>'",
                )

            token = authorization[len(Headers.BEARER_PREFIX) :]
            if not token:
                abort(401, description="Token is empty")

            try:
                claims = verifier.verify(token)
            except TokenExpiredError:
                abort(401, description="Token has expired")
            except InvalidAlgorithmError as e:
                abort(401, description=f"Invalid token algorithm: {e.algorithm}")
            except JWKSFetchError:
                abort(503, description="Failed to fetch JWKS. Please try again later.")
            except TokenValidationError as e:
                abort(401, description=str(e))

            kwargs["user"] = {
                "sub": claims.get("sub", ""),
                "scope": claims.get("scope"),
                "client_id": claims.get("client_id"),
                "iss": claims.get("iss"),
                "aud": claims.get("aud"),
                "exp": claims.get("exp"),
                "iat": claims.get("iat"),
            }

            return func(*args, **kwargs)

        return wrapper

    return decorator

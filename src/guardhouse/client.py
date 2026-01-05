"""Guardhouse API Client with sync/async support and token management."""

import asyncio
import threading
import time
from typing import TYPE_CHECKING, Any

import httpx

from guardhouse.config import (
    IntrospectionCredentialTransmission,
    IntrospectionResponse,
)
from guardhouse.constants import (
    CacheKeys,
    Defaults,
    Endpoints,
    GrantTypes,
    Headers,
)
from guardhouse.exceptions import (
    GuardhouseAuthError,
    GuardhouseConfigError,
    GuardhouseNetworkError,
)

if TYPE_CHECKING:
    pass


class _TokenInfo:
    """Stored token information."""

    def __init__(
        self,
        access_token: str,
        expires_at: float,
        token_type: str = Defaults.DEFAULT_TOKEN_TYPE,
    ) -> None:
        """Initialize token info."""
        self.access_token = access_token
        self.expires_at = expires_at
        self.token_type = token_type

    def is_expired(self, buffer_seconds: int = 0) -> bool:
        """Check if token is expired considering buffer."""
        return time.time() >= (self.expires_at - buffer_seconds)

    def __repr__(self) -> str:
        """Safe repr that doesn't expose token."""
        return f"_TokenInfo(expires_at={self.expires_at})"


class GuardhouseClient:
    """Guardhouse API Client with automatic token management.

    This client supports both synchronous and asynchronous operations.
    It automatically handles token acquisition, caching, and refresh.

    Thundering Herd Protection:
    ---------------------------
    Uses threading.Lock (sync) and asyncio.Lock (async) to prevent
    multiple concurrent requests from refreshing the token simultaneously.
    When a token expires, only one request performs the refresh while
    others wait and reuse the newly fetched token.

    Usage:
    -------
    >>> client = GuardhouseClient(
    ...     authority="https://auth.example.com",
    ...     client_id="my-client",
    ...     client_secret="my-secret",
    ...     scope="api"
    ... )
    >>> token = client.get_access_token()
    >>> response = client.get("https://api.example.com/users")
    """

    def __init__(
        self,
        authority: str,
        client_id: str,
        client_secret: str,
        scope: str = Defaults.DEFAULT_SCOPE,
        request_timeout: int = Defaults.REQUEST_TIMEOUT_SECONDS,
        cache_expiration_buffer: int = Defaults.CACHE_EXPIRATION_BUFFER_SECONDS,
        introspection_client_id: str | None = None,
        introspection_client_secret: str | None = None,
        introspection_credential_transmission: str = IntrospectionCredentialTransmission.BASIC_AUTH,
        max_retry_attempts: int = Defaults.MAX_RETRY_ATTEMPTS,
        enable_http_resilience: bool = True,
    ) -> None:
        """Initialize Guardhouse Client.

        Args:
            authority: Identity server URL
            client_id: Client ID
            client_secret: Client secret
            scope: Requested scope (default: "api")
            request_timeout: HTTP request timeout in seconds
            cache_expiration_buffer: Buffer in seconds before token expiration
            introspection_client_id: Optional client ID for introspection
            introspection_client_secret: Optional client secret for introspection
            introspection_credential_transmission: Method for transmitting introspection credentials
            max_retry_attempts: Maximum number of retry attempts for failed requests
            enable_http_resilience: Enable automatic retry with exponential backoff
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

        if max_retry_attempts < 0:
            raise GuardhouseConfigError(
                f"max_retry_attempts must be >= 0, got: {max_retry_attempts}",
                field="max_retry_attempts",
            )

        self.authority = authority.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.request_timeout = request_timeout
        self.cache_expiration_buffer = cache_expiration_buffer
        self.introspection_client_id = introspection_client_id
        self.introspection_client_secret = introspection_client_secret
        self.introspection_credential_transmission = introspection_credential_transmission
        self.max_retry_attempts = max_retry_attempts
        self.enable_http_resilience = enable_http_resilience

        self._token_cache: dict[str, _TokenInfo] = {}
        self._token_lock = threading.Lock()
        self._async_token_lock = asyncio.Lock()

        self._http_client = httpx.Client(timeout=request_timeout, verify=True)
        self._async_http_client: httpx.AsyncClient | None = None

        self._token_endpoint = f"{self.authority}/{Endpoints.CONNECT_TOKEN}"
        self._introspection_endpoint = f"{self.authority}/{Endpoints.CONNECT_INTROSPECT}"

    @property
    def _async_client(self) -> httpx.AsyncClient:
        """Lazy-initialize async HTTP client."""
        if self._async_http_client is None:
            self._async_http_client = httpx.AsyncClient(timeout=self.request_timeout, verify=True)
        return self._async_http_client

    def _get_cache_key(self) -> str:
        """Get cache key for this client."""
        return f"{CacheKeys.ACCESS_TOKEN}:{self.client_id}"

    def _get_cached_token(self) -> _TokenInfo | None:
        """Get cached token if valid."""
        with self._token_lock:
            token = self._token_cache.get(self._get_cache_key())
            if token is None:
                return None
            if token.is_expired(self.cache_expiration_buffer):
                del self._token_cache[self._get_cache_key()]
                return None
            return token

    def _set_cached_token(self, token_info: _TokenInfo) -> None:
        """Set cached token."""
        with self._token_lock:
            self._token_cache[self._get_cache_key()] = token_info

    def _clear_cached_token(self) -> None:
        """Clear cached token."""
        with self._token_lock:
            self._token_cache.pop(self._get_cache_key(), None)

    def _prepare_token_request(self) -> dict[str, str]:
        """Prepare token request parameters."""
        return {
            "grant_type": GrantTypes.CLIENT_CREDENTIALS,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scope,
        }

    def _retry_request_with_backoff(
        self,
        request_func: Any,
        operation_name: str = "HTTP request",
    ) -> httpx.Response:
        """Execute request with exponential backoff retry.

        Args:
            request_func: Function to execute (returns httpx.Response)
            operation_name: Name of operation for error messages

        Returns:
            httpx.Response

        Raises:
            GuardhouseNetworkError: If all retry attempts fail
        """
        if not self.enable_http_resilience or self.max_retry_attempts == 0:
            return request_func()

        last_exception = None
        for attempt in range(self.max_retry_attempts + 1):
            try:
                response = request_func()

                if response.status_code < 500:
                    return response

                last_exception = GuardhouseNetworkError(
                    f"{operation_name} failed with status {response.status_code}",
                    status_code=response.status_code,
                    url=str(response.url),
                )

            except (httpx.NetworkError, httpx.TimeoutException) as e:
                last_exception = GuardhouseNetworkError(
                    f"{operation_name} network error: {e!s}",
                    url=getattr(e, "request", {}).get("url", ""),
                ) from e

            except httpx.HTTPStatusError as e:
                last_exception = GuardhouseNetworkError(
                    f"{operation_name} HTTP error: {e!s}",
                    status_code=e.response.status_code,
                    url=str(e.response.url),
                ) from e

            if attempt < self.max_retry_attempts:
                backoff_delay = min(2 ** attempt, 30)
                time.sleep(backoff_delay)

        raise last_exception

    def _parse_token_response(self, response: httpx.Response) -> _TokenInfo:
        """Parse token response, handling errors."""
        try:
            data = response.json()
        except Exception as e:
            raise GuardhouseNetworkError(
                f"Failed to parse token response as JSON: {e!s}",
                status_code=response.status_code,
                url=str(response.url),
            ) from e

        if response.status_code != 200:
            error = data.get("error", "unknown")
            error_description = data.get("error_description", "")
            raise GuardhouseAuthError(
                f"Token request failed: {error}. {error_description}",
                error_code=error,
                error_description=error_description,
            )

        access_token = data.get("access_token")
        expires_in = data.get("expires_in", 3600)
        token_type = data.get("token_type", Defaults.DEFAULT_TOKEN_TYPE)

        if not access_token:
            raise GuardhouseAuthError("Token response missing access_token")

        expires_at = time.time() + expires_in
        return _TokenInfo(access_token=access_token, expires_at=expires_at, token_type=token_type)

    def _request_token_sync(self) -> _TokenInfo:
        """Request new access token (sync)."""
        response = self._retry_request_with_backoff(
            lambda: self._http_client.post(
                self._token_endpoint,
                data=self._prepare_token_request(),
                headers={Headers.CONTENT_TYPE: Headers.APPLICATION_URLENCODED},
            ),
            "Token request",
        )
        return self._parse_token_response(response)

    async def _request_token_async(self) -> _TokenInfo:
        """Request new access token (async)."""
        response = await self._async_client.post(
            self._token_endpoint,
            data=self._prepare_token_request(),
            headers={Headers.CONTENT_TYPE: Headers.APPLICATION_URLENCODED},
        )
        return self._parse_token_response(response)

    def get_access_token(self) -> str:
        """Get access token, fetching new one if needed (sync).

        Returns:
            Access token string

        Raises:
            GuardhouseAuthError: If authentication fails
            GuardhouseNetworkError: If network request fails
        """
        token = self._get_cached_token()

        if token is None:
            with self._token_lock:
                token = self._get_cached_token()
                if token is None:
                    token = self._request_token_sync()
                    self._set_cached_token(token)

        return token.access_token

    async def get_access_token_async(self) -> str:
        """Get access token, fetching new one if needed (async).

        Returns:
            Access token string

        Raises:
            GuardhouseAuthError: If authentication fails
            GuardhouseNetworkError: If network request fails
        """
        token = self._get_cached_token()

        if token is None:
            async with self._async_token_lock:
                token = self._get_cached_token()
                if token is None:
                    token = await self._request_token_async()
                    self._set_cached_token(token)

        return token.access_token

    def _refresh_and_retry_sync(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Refresh token and retry request (sync)."""
        with self._token_lock:
            token = self._get_cached_token()
            if token is None or token.is_expired(self.cache_expiration_buffer):
                token = self._request_token_sync()
                self._set_cached_token(token)

        headers = kwargs.get("headers", {})
        headers[Headers.AUTHORIZATION] = f"{Headers.BEARER_PREFIX}{token.access_token}"
        kwargs["headers"] = headers

        return self._http_client.request(method, url, **kwargs)

    async def _refresh_and_retry_async(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response:
        """Refresh token and retry request (async)."""
        async with self._async_token_lock:
            token = self._get_cached_token()
            if token is None or token.is_expired(self.cache_expiration_buffer):
                token = await self._request_token_async()
                self._set_cached_token(token)

        headers = kwargs.get("headers", {})
        headers[Headers.AUTHORIZATION] = f"{Headers.BEARER_PREFIX}{token.access_token}"
        kwargs["headers"] = headers

        return await self._async_client.request(method, url, **kwargs)

    def _execute_request_sync(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute HTTP request with auto-refresh on 401 (sync)."""
        token = self.get_access_token()
        headers = kwargs.get("headers", {})
        headers[Headers.AUTHORIZATION] = f"{Headers.BEARER_PREFIX}{token}"
        kwargs["headers"] = headers

        response = self._http_client.request(method, url, **kwargs)

        if response.status_code == 401:
            self._clear_cached_token()
            return self._refresh_and_retry_sync(method, url, **kwargs)

        return response

    async def _execute_request_async(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute HTTP request with auto-refresh on 401 (async)."""
        token = await self.get_access_token_async()
        headers = kwargs.get("headers", {})
        headers[Headers.AUTHORIZATION] = f"{Headers.BEARER_PREFIX}{token}"
        kwargs["headers"] = headers

        response = await self._async_client.request(method, url, **kwargs)

        if response.status_code == 401:
            self._clear_cached_token()
            return await self._refresh_and_retry_async(method, url, **kwargs)

        return response

    def request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make authenticated HTTP request (sync).

        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional arguments for httpx.request

        Returns:
            httpx.Response

        Raises:
            GuardhouseNetworkError: If request fails
            GuardhouseAuthError: If authentication fails
        """
        return self._execute_request_sync(method, url, **kwargs)

    async def request_async(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make authenticated HTTP request (async).

        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional arguments for httpx.request

        Returns:
            httpx.Response

        Raises:
            GuardhouseNetworkError: If request fails
            GuardhouseAuthError: If authentication fails
        """
        return await self._execute_request_async(method, url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make authenticated GET request (sync)."""
        return self.request("GET", url, **kwargs)

    async def get_async(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make authenticated GET request (async)."""
        return await self.request_async("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make authenticated POST request (sync)."""
        return self.request("POST", url, **kwargs)

    async def post_async(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make authenticated POST request (async)."""
        return await self.request_async("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make authenticated PUT request (sync)."""
        return self.request("PUT", url, **kwargs)

    async def put_async(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make authenticated PUT request (async)."""
        return await self.request_async("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make authenticated DELETE request (sync)."""
        return self.request("DELETE", url, **kwargs)

    async def delete_async(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make authenticated DELETE request (async)."""
        return await self.request_async("DELETE", url, **kwargs)

    def introspect_token(self, token: str) -> IntrospectionResponse:
        """Introspect token to check if it's active (sync).

        Args:
            token: Token to introspect

        Returns:
            IntrospectionResponse

        Raises:
            GuardhouseConfigError: If introspection credentials not configured
            GuardhouseNetworkError: If network request fails
        """
        from guardhouse.constants import SecurityDefaults

        if not self.introspection_client_id or not self.introspection_client_secret:
            raise GuardhouseConfigError(
                "Introspection credentials not configured. "
                "Set introspection_client_id and introspection_client_secret.",
                field="introspection_client_id",
            )

        if len(token) > SecurityDefaults.MAX_TOKEN_LENGTH:
            raise GuardhouseConfigError(
                f"Token too long (max {SecurityDefaults.MAX_TOKEN_LENGTH} characters)",
                field="token",
            )

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
            data["client_id"] = self.introspection_client_id
            data["client_secret"] = self.introspection_client_secret

        response = self._http_client.post(self._introspection_endpoint, headers=headers, data=data)
        response.raise_for_status()

        return IntrospectionResponse(**response.json())

    async def introspect_token_async(self, token: str) -> IntrospectionResponse:
        """Introspect token to check if it's active (async).

        Args:
            token: Token to introspect

        Returns:
            IntrospectionResponse

        Raises:
            GuardhouseConfigError: If introspection credentials not configured
            GuardhouseNetworkError: If network request fails
        """
        from guardhouse.constants import SecurityDefaults

        if not self.introspection_client_id or not self.introspection_client_secret:
            raise GuardhouseConfigError(
                "Introspection credentials not configured. "
                "Set introspection_client_id and introspection_client_secret.",
                field="introspection_client_id",
            )

        if len(token) > SecurityDefaults.MAX_TOKEN_LENGTH:
            raise GuardhouseConfigError(
                f"Token too long (max {SecurityDefaults.MAX_TOKEN_LENGTH} characters)",
                field="token",
            )

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
            data["client_id"] = self.introspection_client_id
            data["client_secret"] = self.introspection_client_secret

        response = await self._async_client.post(
            self._introspection_endpoint, headers=headers, data=data
        )
        response.raise_for_status()

        return IntrospectionResponse(**response.json())

    def is_token_active(self, token: str) -> bool:
        """Check if token is active using introspection (sync).

        Args:
            token: Token to check

        Returns:
            True if token is active, False otherwise
        """
        try:
            result = self.introspect_token(token)
            return result.active
        except Exception:
            return False

    async def is_token_active_async(self, token: str) -> bool:
        """Check if token is active using introspection (async).

        Args:
            token: Token to check

        Returns:
            True if token is active, False otherwise
        """
        try:
            result = await self.introspect_token_async(token)
            return result.active
        except Exception:
            return False

    def close(self) -> None:
        """Close the HTTP client (sync)."""
        self._http_client.close()

    async def close_async(self) -> None:
        """Close the async HTTP client."""
        if self._async_http_client is not None:
            await self._async_http_client.aclose()

    def __enter__(self) -> "GuardhouseClient":
        """Context manager support (sync)."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager support (sync)."""
        self.close()

    async def __aenter__(self) -> "GuardhouseClient":
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
        """Safe repr that doesn't expose secrets."""
        return (
            f"GuardhouseClient(authority={self.authority!r}, "
            f"client_id={self.client_id!r}, scope={self.scope!r})"
        )

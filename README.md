# Guardhouse Python SDK

Python SDK for Guardhouse authentication, supporting both **Machine-to-Machine (M2M)** client and **resource server** token validation.

## Features

- ✅ **Dual Mode Support**: M2M client for backend services and resource server validation
- ✅ **Sync & Async**: Full support for both synchronous and asynchronous operations
- ✅ **Automatic Token Management**: Token caching, auto-refresh, and thread-safe operations
- ✅ **Strict Security**: Algorithm enforcement (RS256 only), JWKS caching, introspection
- ✅ **Framework Integrations**: Batteries-included helpers for FastAPI and Flask
- ✅ **Type Hints**: Fully typed for Python 3.9+ (passes `mypy --strict`)
- ✅ **Production Ready**: HTTP resilience with retry, comprehensive error handling

## Installation

```bash
pip install guardhouse-sdk
```

### Optional Dependencies

For framework integrations:

```bash
# FastAPI
pip install guardhouse-sdk[fastapi]

# Flask
pip install guardhouse-sdk[flask]
```

## Quick Start

### M2M Client (Backend Service)

Authenticate your backend service to call Guardhouse APIs:

```python
from guardhouse import GuardhouseClient

client = GuardhouseClient(
    authority="https://auth.example.com",
    client_id="my-service",
    client_secret="your-secret-here",
    scope="api"
)

# Get access token automatically (cached)
token = client.get_access_token()

# Make authenticated requests
response = client.get("https://api.example.com/users")
users = response.json()

# Async support
async def fetch_users():
    token = await client.get_access_token_async()
    response = await client.get_async("https://api.example.com/users")
    return response.json()
```

### Resource Server (Token Validation)

Validate incoming Bearer tokens to protect your API:

```python
from guardhouse import TokenVerifier, TokenExpiredError, TokenValidationError

verifier = TokenVerifier(
    authority="https://auth.example.com",
    audience="my-api"
)

def protected_route(request):
    # Extract token from Authorization header
    token = request.headers.get("Authorization", "").replace("Bearer ", "")

    try:
        claims = verifier.verify(token)
        print(f"Authenticated user: {claims['sub']}")

        # Check scopes
        TokenVerifier.has_scope("read:users", claims.get("scope"))

    except TokenExpiredError:
        return {"error": "Token expired"}, 401
    except TokenValidationError as e:
        return {"error": str(e)}, 401
```

## Framework Integrations

### FastAPI

```python
from fastapi import FastAPI, Depends, HTTPException
from guardhouse.middleware import requires_auth, User

app = FastAPI()

# Create auth dependency
get_user = requires_auth(
    authority="https://auth.example.com",
    audience="my-api"
)

@app.get("/protected")
async def protected_route(user: User = Depends(get_user)):
    return {"message": f"Hello, {user.sub}!"}

@app.get("/admin")
async def admin_route(user: User = Depends(get_user)):
    if not user.has_scope("admin"):
        raise HTTPException(status_code=403, detail="Admin scope required")
    return {"message": "Welcome admin!"}
```

### Flask

```python
from flask import Flask, request
from guardhouse.middleware import FlaskAuthExtension

app = Flask(__name__)

# Initialize extension
auth = FlaskAuthExtension(
    app=app,
    authority="https://auth.example.com",
    audience="my-api"
)

@app.route("/protected")
@auth.requires_auth
def protected(user):
    return {"message": f"Hello, {user['sub']}!"}

@app.route("/admin")
@auth.requires_auth(required_scope="admin")
def admin(user):
    return {"message": "Welcome admin!"}
```

## Advanced Configuration

### Client Configuration

```python
from guardhouse import GuardhouseClient

client = GuardhouseClient(
    authority="https://auth.example.com",
    client_id="my-service",
    client_secret="your-secret",
    scope="api read write",

    # Token caching
    cache_expiration_buffer=60,  # Refresh 60s before expiry

    # Retry logic
    max_retry_attempts=3,
    request_timeout=30,
    enable_http_resilience=True,

    # Introspection (optional)
    introspection_client_id="introspection-client",
    introspection_client_secret="introspection-secret",
    introspection_credential_transmission="basic_auth",
)
```

### Verifier Configuration

```python
from guardhouse import TokenVerifier

verifier = TokenVerifier(
    authority="https://auth.example.com",
    audience="my-api",

    # Validation mode
    validation_mode="jwt_signature",  # or "introspection"

    # Introspection (if using introspection mode)
    introspection_client_id="introspection-client",
    introspection_client_secret="introspection-secret",

    # JWKS caching
    jwks_cache_duration_hours=24,
    jwks_refresh_interval_minutes=5,

    # Security
    validate_issuer=True,
    validate_audience=True,
    validate_lifetime=True,
    valid_algorithms=["RS256"],
    clock_skew_minutes=5.0,
)
```

## Security Features

The SDK implements comprehensive security protections:

- ✅ **Algorithm Enforcement**: Strict RS256 only, rejects "none" algorithm
- ✅ **Issuer Validation**: Verifies token issuer matches configured authority
- ✅ **Audience Validation**: Ensures token is intended for your API
- ✅ **Expiration Validation**: Rejects expired tokens (with configurable clock skew)
- ✅ **JWKS Caching**: Prevents DDoS on auth server with rate-limited refreshes
- ✅ **Scope Checking**: Helper method to validate user permissions
- ✅ **Safe Logging**: Secrets redacted from all logs and error messages
- ✅ **Thread Safety**: Token cache is protected with RLock
- ✅ **Token Type Validation**: Ensures token type is "JWT"

## Error Handling

```python
from guardhouse import (
    GuardhouseError,
    GuardhouseConfigError,
    GuardhouseAuthError,
    GuardhouseNetworkError,
    TokenValidationError,
    TokenExpiredError,
    InvalidAlgorithmError,
    ScopeError,
)

try:
    claims = verifier.verify(token)
except TokenExpiredError:
    # Token has expired
    pass
except InvalidAlgorithmError as e:
    # Invalid algorithm (e.g., "none")
    print(f"Algorithm: {e.algorithm}")
    pass
except TokenValidationError:
    # Generic validation error
    pass
except GuardhouseAuthError as e:
    # Authentication failed
    print(f"Error: {e.error_code}")
    print(f"Description: {e.error_description}")
    pass
except GuardhouseNetworkError as e:
    # Network request failed
    print(f"Status: {e.status_code}")
    print(f"URL: {e.url}")
    pass
```

## Development

### Setup Development Environment

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run type checking
mypy --strict src/

# Run linting
ruff check src/
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/guardhouse --cov-report=html

# Run specific test file
pytest tests/test_verifier.py
```

## Project Structure

```
guardhouse-sdk-python/
├── src/
│   └── guardhouse/
│       ├── __init__.py          # Public API
│       ├── client.py            # M2M client
│       ├── verifier.py          # Token verifier
│       ├── config.py            # Configuration models
│       ├── constants.py         # Constants
│       ├── exceptions.py        # Custom exceptions
│       └── middleware/        # Framework integrations
│           ├── __init__.py
│           ├── fastapi.py
│           └── flask.py
├── tests/
│   └── test_verifier.py       # Unit tests
├── pyproject.toml             # Project configuration
└── README.md
```

## License

Apache-2.0 License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## Support

For issues and questions:
- GitHub Issues: https://github.com/legiosoft/guardhouse-sdk-python/issues
- Documentation: https://docs.guardhouse.cloud

"""Guardhouse Python SDK.

A production-grade SDK for Guardhouse authentication.
Supports both Machine-to-Machine (M2M) client and resource server validation.

Usage:
-------
**Client (M2M):**
```python
from guardhouse import GuardhouseClient

client = GuardhouseClient(
    authority="https://auth.example.com",
    client_id="my-client",
    client_secret="my-secret",
    scope="api"
)

token = client.get_access_token()
response = client.get("https://api.example.com/users")
```

**Resource Server (Token Validation):**
```python
from guardhouse import TokenVerifier

verifier = TokenVerifier(
    authority="https://auth.example.com",
    audience="my-api"
)

try:
    claims = verifier.verify(token)
    print(f"User: {claims['sub']}")
    TokenVerifier.has_scope("read:users", claims.get("scope"))
except TokenExpiredError:
    print("Token expired")
except TokenValidationError as e:
    print(f"Invalid token: {e}")
```

**FastAPI Integration:**
```python
from fastapi import FastAPI, Depends
from guardhouse.middleware import requires_auth, User

app = FastAPI()
get_user = requires_auth(
    authority="https://auth.example.com",
    audience="my-api"
)

@app.get("/protected")
async def protected_route(user: User = Depends(get_user)):
    return {"message": f"Hello, {user.sub}!"}
```

**Flask Integration:**
```python
from flask import Flask
from guardhouse.middleware import FlaskAuthExtension

app = Flask(__name__)
auth = FlaskAuthExtension(app, authority="https://auth.example.com", audience="my-api")

@app.route("/protected")
@auth.requires_auth
def protected():
    return {"message": "Hello!"}
```
"""

from guardhouse.client import GuardhouseClient
from guardhouse.config import IntrospectionResponse
from guardhouse.constants import (
    Algorithms,
    CacheKeys,
    Defaults,
    Endpoints,
    Headers,
)
from guardhouse.exceptions import (
    GuardhouseAuthError,
    GuardhouseConfigError,
    GuardhouseError,
    GuardhouseNetworkError,
    InvalidAlgorithmError,
    JWKSFetchError,
    ScopeError,
    TokenExpiredError,
    TokenRefreshError,
    TokenValidationError,
)
from guardhouse.verifier import TokenVerifier

__version__ = "0.1.0"
__all__ = [
    "GuardhouseClient",
    "TokenVerifier",
    "IntrospectionResponse",
    "GuardhouseError",
    "GuardhouseConfigError",
    "GuardhouseAuthError",
    "GuardhouseNetworkError",
    "TokenValidationError",
    "TokenExpiredError",
    "InvalidAlgorithmError",
    "ScopeError",
    "TokenRefreshError",
    "JWKSFetchError",
    "Algorithms",
    "Endpoints",
    "Headers",
    "CacheKeys",
    "Defaults",
]

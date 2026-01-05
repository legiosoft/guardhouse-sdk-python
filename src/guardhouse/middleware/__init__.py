"""Middleware package for framework integrations."""

from guardhouse.middleware.fastapi import (
    User,
    requires_auth,
    requires_auth_async,
    requires_scope,
)
from guardhouse.middleware.flask import (
    FlaskAuthExtension,
    create_auth_decorator,
)

__all__ = [
    "FlaskAuthExtension",
    "create_auth_decorator",
    "requires_auth",
    "requires_auth_async",
    "requires_scope",
    "User",
]

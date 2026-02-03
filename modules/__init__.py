"""Incident Management modules - secure OAuth auth and auth store."""

from .auth import (
    AuthManager,
    DemoAuthManager,
    get_auth_manager,
    require_auth,
    has_permission,
    get_role_for_user,
    AuthConfig,
)
from . import auth_store

__all__ = [
    "AuthManager",
    "DemoAuthManager",
    "get_auth_manager",
    "require_auth",
    "has_permission",
    "get_role_for_user",
    "AuthConfig",
    "auth_store",
]

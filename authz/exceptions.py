"""
Custom exceptions for the authorization framework.
"""


class AuthzException(Exception):
    """Base exception for all authorization framework errors."""
    pass


class PolicyEvaluationError(AuthzException):
    """Raised when a policy evaluation fails unexpectedly."""
    pass


class InvalidPermissionCode(AuthzException):
    """Raised when a permission code has an invalid format."""
    pass


class RoleNotFound(AuthzException):
    """Raised when a requested role does not exist."""
    pass


class PermissionNotFound(AuthzException):
    """Raised when a requested permission does not exist."""
    pass


class PolicyRegistrationError(AuthzException):
    """Raised when there's an error registering a policy."""
    pass

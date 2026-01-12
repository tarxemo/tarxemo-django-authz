"""
Utility functions for the authorization framework.
"""

import re
from typing import List, Tuple, Optional
from django.db.models import QuerySet

from .exceptions import InvalidPermissionCode


def validate_permission_code(code: str) -> bool:
    """
    Validate that a permission code follows the expected format.
    
    Valid formats:
    - "namespace.action" (e.g., "courses.view")
    - "namespace.resource.action" (e.g., "courses.enrollment.create")
    
    Args:
        code: Permission code to validate
        
    Returns:
        bool: True if valid
        
    Raises:
        InvalidPermissionCode: If code is invalid
    """
    if not code or not isinstance(code, str):
        raise InvalidPermissionCode("Permission code must be a non-empty string")
    
    # Must contain at least one dot
    if '.' not in code:
        raise InvalidPermissionCode(
            f"Permission code '{code}' must follow format 'namespace.action'"
        )
    
    # Must not start or end with a dot
    if code.startswith('.') or code.endswith('.'):
        raise InvalidPermissionCode(
            f"Permission code '{code}' cannot start or end with a dot"
        )
    
    # Must not contain consecutive dots
    if '..' in code:
        raise InvalidPermissionCode(
            f"Permission code '{code}' cannot contain consecutive dots"
        )
    
    # Should only contain alphanumeric, dots, underscores, and hyphens
    if not re.match(r'^[a-zA-Z0-9._-]+$', code):
        raise InvalidPermissionCode(
            f"Permission code '{code}' contains invalid characters"
        )
    
    return True


def parse_permission_code(code: str) -> Tuple[str, str, Optional[str]]:
    """
    Parse a permission code into its components.
    
    Args:
        code: Permission code (e.g., "courses.enroll" or "courses.enrollment.create")
        
    Returns:
        tuple: (namespace, action, resource) where resource is optional
        
    Examples:
        >>> parse_permission_code("courses.view")
        ("courses", "view", None)
        
        >>> parse_permission_code("courses.enrollment.create")
        ("courses", "create", "enrollment")
    """
    validate_permission_code(code)
    
    parts = code.split('.')
    
    if len(parts) == 2:
        # Format: namespace.action
        return parts[0], parts[1], None
    elif len(parts) >= 3:
        # Format: namespace.resource.action (or more parts)
        # Take first as namespace, last as action, middle parts as resource
        namespace = parts[0]
        action = parts[-1]
        resource = '.'.join(parts[1:-1])
        return namespace, action, resource
    else:
        # Should not reach here due to validation
        raise InvalidPermissionCode(f"Invalid permission code format: {code}")


def get_all_permissions() -> QuerySet:
    """
    Get all permissions in the system.
    
    Returns:
        QuerySet: All Permission objects
    """
    from .models import Permission
    return Permission.objects.all()


def get_all_roles() -> QuerySet:
    """
    Get all roles in the system.
    
    Returns:
        QuerySet: All Role objects
    """
    from .models import Role
    return Role.objects.all()


def get_active_permissions() -> QuerySet:
    """
    Get all active permissions.
    
    Returns:
        QuerySet: Active Permission objects
    """
    from .models import Permission
    return Permission.objects.filter(is_active=True)


def get_active_roles() -> QuerySet:
    """
    Get all active roles.
    
    Returns:
        QuerySet: Active Role objects
    """
    from .models import Role
    return Role.objects.filter(is_active=True)


def permission_exists(code: str) -> bool:
    """
    Check if a permission exists.
    
    Args:
        code: Permission code to check
        
    Returns:
        bool: True if permission exists
    """
    from .models import Permission
    return Permission.objects.filter(code=code).exists()


def role_exists(name: str) -> bool:
    """
    Check if a role exists.
    
    Args:
        name: Role name to check
        
    Returns:
        bool: True if role exists
    """
    from .models import Role
    return Role.objects.filter(name=name).exists()


def get_permission_by_code(code: str):
    """
    Get a permission by its code.
    
    Args:
        code: Permission code
        
    Returns:
        Permission: Permission object
        
    Raises:
        Permission.DoesNotExist: If permission doesn't exist
    """
    from .models import Permission
    return Permission.objects.get(code=code)


def get_role_by_name(name: str):
    """
    Get a role by its name.
    
    Args:
        name: Role name
        
    Returns:
        Role: Role object
        
    Raises:
        Role.DoesNotExist: If role doesn't exist
    """
    from .models import Role
    return Role.objects.get(name=name)


def create_permission(code: str, description: str = "") -> 'Permission':
    """
    Create a new permission.
    
    Args:
        code: Permission code
        description: Optional description
        
    Returns:
        Permission: Created permission
        
    Raises:
        InvalidPermissionCode: If code is invalid
        IntegrityError: If permission already exists
    """
    from .models import Permission
    validate_permission_code(code)
    return Permission.objects.create(code=code, description=description)


def create_role(name: str, description: str = "") -> 'Role':
    """
    Create a new role.
    
    Args:
        name: Role name
        description: Optional description
        
    Returns:
        Role: Created role
    """
    from .models import Role
    return Role.objects.create(name=name, description=description)

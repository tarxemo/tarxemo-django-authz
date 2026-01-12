"""
High-level service functions for authorization management.

These functions provide a clean API for common authorization operations
like assigning roles, granting permissions, etc.
"""

import logging
from typing import List, Optional, Dict, Any
from django.contrib.auth import get_user_model
from django.db import transaction

from .models import Permission, Role, UserRole, UserPermission
from .exceptions import RoleNotFound, PermissionNotFound
from .utils import get_permission_by_code, get_role_by_name


logger = logging.getLogger(__name__)
User = get_user_model()


# ============================================================================
# Role Management
# ============================================================================


@transaction.atomic
def assign_role(user, role_name: str, created_by=None) -> UserRole:
    """
    Assign a role to a user.
    
    Args:
        user: User to assign role to
        role_name: Name of the role
        created_by: User who is assigning the role (optional)
        
    Returns:
        UserRole: Created UserRole instance
        
    Raises:
        RoleNotFound: If role doesn't exist
    """
    try:
        role = get_role_by_name(role_name)
    except Role.DoesNotExist:
        raise RoleNotFound(f"Role '{role_name}' does not exist")
    
    user_role, created = UserRole.objects.get_or_create(
        user=user,
        role=role,
        defaults={'created_by': created_by}
    )
    
    if created:
        logger.info(f"Assigned role '{role_name}' to user {user}")
    else:
        logger.debug(f"User {user} already has role '{role_name}'")
    
    return user_role


@transaction.atomic
def revoke_role(user, role_name: str) -> bool:
    """
    Revoke a role from a user.
    
    Args:
        user: User to revoke role from
        role_name: Name of the role
        
    Returns:
        bool: True if role was revoked, False if user didn't have the role
    """
    try:
        role = get_role_by_name(role_name)
    except Role.DoesNotExist:
        logger.warning(f"Attempted to revoke non-existent role '{role_name}'")
        return False
    
    deleted_count, _ = UserRole.objects.filter(user=user, role=role).delete()
    
    if deleted_count > 0:
        logger.info(f"Revoked role '{role_name}' from user {user}")
        return True
    else:
        logger.debug(f"User {user} did not have role '{role_name}'")
        return False


def get_user_roles(user) -> List[Role]:
    """
    Get all roles assigned to a user.
    
    Args:
        user: User to check
        
    Returns:
        List[Role]: List of Role objects
    """
    return list(
        Role.objects.filter(
            user_assignments__user=user,
            is_active=True
        ).distinct()
    )


def get_user_role_names(user) -> List[str]:
    """
    Get all role names assigned to a user.
    
    Args:
        user: User to check
        
    Returns:
        List[str]: List of role names
    """
    return list(
        Role.objects.filter(
            user_assignments__user=user,
            is_active=True
        ).values_list('name', flat=True).distinct()
    )


def user_has_role(user, role_name: str) -> bool:
    """
    Check if a user has a specific role.
    
    Args:
        user: User to check
        role_name: Role name to check
        
    Returns:
        bool: True if user has the role
    """
    return UserRole.objects.filter(
        user=user,
        role__name=role_name,
        role__is_active=True
    ).exists()


@transaction.atomic
def bulk_assign_roles(users: List, role_names: List[str], created_by=None) -> int:
    """
    Assign multiple roles to multiple users.
    
    Args:
        users: List of users
        role_names: List of role names
        created_by: User who is assigning the roles (optional)
        
    Returns:
        int: Number of role assignments created
        
    Raises:
        RoleNotFound: If any role doesn't exist
    """
    # Validate all roles exist first
    roles = []
    for role_name in role_names:
        try:
            role = get_role_by_name(role_name)
            roles.append(role)
        except Role.DoesNotExist:
            raise RoleNotFound(f"Role '{role_name}' does not exist")
    
    # Create assignments
    created_count = 0
    for user in users:
        for role in roles:
            _, created = UserRole.objects.get_or_create(
                user=user,
                role=role,
                defaults={'created_by': created_by}
            )
            if created:
                created_count += 1
    
    logger.info(
        f"Bulk assigned {len(role_names)} roles to {len(users)} users "
        f"({created_count} new assignments)"
    )
    
    return created_count


# ============================================================================
# Permission Management
# ============================================================================


@transaction.atomic
def grant_permission(user, permission_code: str, created_by=None) -> UserPermission:
    """
    Grant a permission directly to a user (explicit allow).
    
    Args:
        user: User to grant permission to
        permission_code: Permission code
        created_by: User who is granting the permission (optional)
        
    Returns:
        UserPermission: Created or updated UserPermission instance
        
    Raises:
        PermissionNotFound: If permission doesn't exist
    """
    try:
        permission = get_permission_by_code(permission_code)
    except Permission.DoesNotExist:
        raise PermissionNotFound(f"Permission '{permission_code}' does not exist")
    
    user_perm, created = UserPermission.objects.update_or_create(
        user=user,
        permission=permission,
        defaults={'allow': True, 'created_by': created_by}
    )
    
    if created:
        logger.info(f"Granted permission '{permission_code}' to user {user}")
    else:
        logger.info(f"Updated permission '{permission_code}' for user {user} to ALLOW")
    
    return user_perm


@transaction.atomic
def deny_permission(user, permission_code: str, created_by=None) -> UserPermission:
    """
    Deny a permission for a user (explicit deny).
    
    This overrides any role-based permissions.
    
    Args:
        user: User to deny permission for
        permission_code: Permission code
        created_by: User who is denying the permission (optional)
        
    Returns:
        UserPermission: Created or updated UserPermission instance
        
    Raises:
        PermissionNotFound: If permission doesn't exist
    """
    try:
        permission = get_permission_by_code(permission_code)
    except Permission.DoesNotExist:
        raise PermissionNotFound(f"Permission '{permission_code}' does not exist")
    
    user_perm, created = UserPermission.objects.update_or_create(
        user=user,
        permission=permission,
        defaults={'allow': False, 'created_by': created_by}
    )
    
    if created:
        logger.info(f"Denied permission '{permission_code}' for user {user}")
    else:
        logger.info(f"Updated permission '{permission_code}' for user {user} to DENY")
    
    return user_perm


@transaction.atomic
def revoke_user_permission(user, permission_code: str) -> bool:
    """
    Revoke a direct user permission override.
    
    This removes the explicit allow/deny, falling back to role-based permissions.
    
    Args:
        user: User to revoke permission from
        permission_code: Permission code
        
    Returns:
        bool: True if permission was revoked, False if user didn't have override
    """
    try:
        permission = get_permission_by_code(permission_code)
    except Permission.DoesNotExist:
        logger.warning(
            f"Attempted to revoke non-existent permission '{permission_code}'"
        )
        return False
    
    deleted_count, _ = UserPermission.objects.filter(
        user=user,
        permission=permission
    ).delete()
    
    if deleted_count > 0:
        logger.info(f"Revoked permission override '{permission_code}' from user {user}")
        return True
    else:
        logger.debug(f"User {user} did not have permission override '{permission_code}'")
        return False


def get_user_permissions(user, include_roles: bool = True) -> List[Dict[str, Any]]:
    """
    Get all permissions for a user with their sources.
    
    Args:
        user: User to check
        include_roles: Whether to include role-based permissions
        
    Returns:
        List[Dict]: List of permission dictionaries with metadata
        
    Example:
        [
            {
                'code': 'courses.enroll',
                'source': 'explicit_allow',
                'role': None
            },
            {
                'code': 'courses.view',
                'source': 'role',
                'role': 'Student'
            }
        ]
    """
    permissions = []
    
    # Get explicit permissions
    user_perms = UserPermission.objects.filter(
        user=user,
        permission__is_active=True
    ).select_related('permission')
    
    for user_perm in user_perms:
        permissions.append({
            'code': user_perm.permission.code,
            'description': user_perm.permission.description,
            'source': 'explicit_allow' if user_perm.allow else 'explicit_deny',
            'role': None,
            'allow': user_perm.allow
        })
    
    # Get role-based permissions
    if include_roles:
        user_roles = UserRole.objects.filter(
            user=user,
            role__is_active=True
        ).select_related('role').prefetch_related('role__permissions')
        
        for user_role in user_roles:
            role_perms = user_role.role.permissions.filter(is_active=True)
            for perm in role_perms:
                # Check if already in list from explicit permission
                if not any(p['code'] == perm.code for p in permissions):
                    permissions.append({
                        'code': perm.code,
                        'description': perm.description,
                        'source': 'role',
                        'role': user_role.role.name,
                        'allow': True
                    })
    
    return permissions


def get_permission_matrix(user) -> Dict[str, Any]:
    """
    Get a comprehensive permission matrix for a user.
    
    Args:
        user: User to check
        
    Returns:
        Dict: Permission matrix with roles and permissions
        
    Example:
        {
            'user': user,
            'is_superuser': False,
            'roles': ['Student', 'TA'],
            'explicit_allows': ['courses.enroll'],
            'explicit_denies': [],
            'role_permissions': {
                'Student': ['courses.view', 'courses.enroll'],
                'TA': ['courses.grade']
            },
            'all_permissions': ['courses.view', 'courses.enroll', 'courses.grade']
        }
    """
    matrix = {
        'user': user,
        'is_superuser': user.is_superuser if user and user.is_authenticated else False,
        'roles': [],
        'explicit_allows': [],
        'explicit_denies': [],
        'role_permissions': {},
        'all_permissions': []
    }
    
    if not user or not user.is_authenticated:
        return matrix
    
    # Get roles
    user_roles = UserRole.objects.filter(
        user=user,
        role__is_active=True
    ).select_related('role').prefetch_related('role__permissions')
    
    for user_role in user_roles:
        role_name = user_role.role.name
        matrix['roles'].append(role_name)
        
        role_perms = list(
            user_role.role.permissions.filter(is_active=True).values_list('code', flat=True)
        )
        matrix['role_permissions'][role_name] = role_perms
    
    # Get explicit permissions
    user_perms = UserPermission.objects.filter(
        user=user,
        permission__is_active=True
    ).select_related('permission')
    
    for user_perm in user_perms:
        if user_perm.allow:
            matrix['explicit_allows'].append(user_perm.permission.code)
        else:
            matrix['explicit_denies'].append(user_perm.permission.code)
    
    # Calculate all effective permissions
    all_perms = set()
    
    # Add role permissions
    for role_perms in matrix['role_permissions'].values():
        all_perms.update(role_perms)
    
    # Add explicit allows
    all_perms.update(matrix['explicit_allows'])
    
    # Remove explicit denies
    for deny in matrix['explicit_denies']:
        all_perms.discard(deny)
    
    matrix['all_permissions'] = sorted(list(all_perms))
    
    return matrix


# ============================================================================
# Utility Functions
# ============================================================================


def get_users_with_permission(permission_code: str) -> List:
    """
    Find all users who have a specific permission.
    
    This includes users with the permission via roles or explicit grants.
    
    Args:
        permission_code: Permission code to search for
        
    Returns:
        List[User]: List of users with the permission
    """
    try:
        permission = get_permission_by_code(permission_code)
    except Permission.DoesNotExist:
        return []
    
    # Users with explicit allow
    explicit_users = User.objects.filter(
        user_permissions__permission=permission,
        user_permissions__allow=True
    )
    
    # Users with permission via roles
    role_users = User.objects.filter(
        user_roles__role__permissions=permission,
        user_roles__role__is_active=True
    )
    
    # Combine and exclude explicit denies
    all_users = (explicit_users | role_users).distinct()
    
    # Exclude users with explicit deny
    denied_users = User.objects.filter(
        user_permissions__permission=permission,
        user_permissions__allow=False
    )
    
    return list(all_users.exclude(id__in=denied_users))


def get_users_with_role(role_name: str) -> List:
    """
    Find all users who have a specific role.
    
    Args:
        role_name: Role name to search for
        
    Returns:
        List[User]: List of users with the role
    """
    return list(
        User.objects.filter(
            user_roles__role__name=role_name,
            user_roles__role__is_active=True
        ).distinct()
    )

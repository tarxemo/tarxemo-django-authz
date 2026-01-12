"""
Central authorization engine.

This module provides the core authorization logic that evaluates whether
a user has permission to perform an action. It integrates RBAC and PBAC.

The main entry point is the authorize() function.
"""

import logging
from typing import Optional, Dict, Any, Tuple

from django.contrib.auth import get_user_model
from django.db.models import Q

from .models import Permission, UserPermission, UserRole
from .policies import policy_registry
from .exceptions import PolicyEvaluationError


logger = logging.getLogger(__name__)
User = get_user_model()


def authorize(
    user,
    permission_code: str,
    obj=None,
    context: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Evaluate if user has permission to perform an action.
    
    This is the main entry point for authorization checks.
    
    Evaluation order (deny-first approach):
    1. Anonymous users → DENY (unless policies allow)
    2. Superusers → ALLOW (bypass all checks)
    3. Explicit user deny (UserPermission with allow=False) → DENY
    4. Explicit user allow (UserPermission with allow=True) → ALLOW
    5. Role-based permission → ALLOW
    6. Policy rules (all must pass) → ALLOW if all pass
    7. Model-level default (if obj has permission metadata) → ALLOW/DENY
    8. Default deny → DENY
    
    Args:
        user: User requesting permission (can be AnonymousUser)
        permission_code: Permission code (e.g., "courses.enroll")
        obj: Object being accessed (optional)
        context: Additional context dict (optional)
        
    Returns:
        bool: True if authorized, False otherwise
        
    Example:
        >>> authorize(user, "courses.enroll", course_obj)
        True
        
        >>> authorize(user, "documents.delete", document, {"reason": "cleanup"})
        False
    """
    if context is None:
        context = {}
    
    # Add object context if available
    if obj and hasattr(obj, 'get_permission_context'):
        obj_context = obj.get_permission_context()
        context = {**obj_context, **context}
    
    logger.debug(
        f"Authorizing user={user} permission={permission_code} "
        f"obj={obj} context={context}"
    )
    
    # Step 1: Check if user is authenticated
    # Anonymous users are denied by default
    if not user or not user.is_authenticated:
        logger.debug("User is not authenticated - access denied")
        return False
    
    # Step 2: Superusers bypass all checks
    if user.is_superuser:
        logger.debug("User is superuser - access granted")
        return True
    
    # Step 3 & 4: Check explicit user permissions (deny first, then allow)
    has_explicit, is_allowed = _check_explicit_user_permission(user, permission_code)
    if has_explicit:
        logger.debug(
            f"Explicit user permission: {'ALLOW' if is_allowed else 'DENY'}"
        )
        return is_allowed
    
    # Step 5: Check role-based permissions
    if _check_role_permission(user, permission_code):
        logger.debug("Access granted via role-based permission")
        
        # Even with role permission, policies must still pass
        allowed, reason = _evaluate_policies(user, permission_code, obj, context)
        if not allowed:
            logger.info(
                f"Role permission overridden by policy: {reason}"
            )
            return False
        
        return True
    
    # Step 6: Policies alone cannot grant access
    # They can only constrain what RBAC grants
    # If we reach here, user has no RBAC grants, so check model defaults
    
    # Step 7: Check model-level defaults
    if obj and hasattr(obj, 'has_permission_metadata'):
        default_allowed = _check_model_default(obj, user, permission_code, context)
        if default_allowed is not None:
            logger.debug(
                f"Model default: {'ALLOW' if default_allowed else 'DENY'}"
            )
            # Even if model allows, policies must pass
            if default_allowed:
                allowed, reason = _evaluate_policies(user, permission_code, obj, context)
                if not allowed:
                    logger.info(f"Model default overridden by policy: {reason}")
                    return False
            return default_allowed
    
    # Step 8: Default deny
    logger.debug(f"Access denied by default for {permission_code}")
    return False


def _check_explicit_user_permission(user, permission_code: str) -> Tuple[bool, bool]:
    """
    Check for explicit user permission overrides.
    
    Args:
        user: User to check
        permission_code: Permission code
        
    Returns:
        tuple: (has_explicit: bool, is_allowed: bool)
               has_explicit=True if user has explicit override
               is_allowed=True if explicitly allowed, False if denied
    """
    try:
        # First check for explicit deny
        deny_exists = UserPermission.objects.filter(
            user=user,
            permission__code=permission_code,
            permission__is_active=True,
            allow=False
        ).exists()
        
        if deny_exists:
            return True, False
        
        # Then check for explicit allow
        allow_exists = UserPermission.objects.filter(
            user=user,
            permission__code=permission_code,
            permission__is_active=True,
            allow=True
        ).exists()
        
        if allow_exists:
            return True, True
        
        # No explicit permission
        return False, False
        
    except Exception as e:
        logger.error(f"Error checking explicit user permission: {e}", exc_info=True)
        return False, False


def _check_role_permission(user, permission_code: str) -> bool:
    """
    Check if user has permission through their roles.
    
    Args:
        user: User to check
        permission_code: Permission code
        
    Returns:
        bool: True if user has permission via roles
    """
    try:
        # Get all active roles for the user
        user_roles = UserRole.objects.filter(
            user=user,
            role__is_active=True
        ).select_related('role')
        
        if not user_roles.exists():
            return False
        
        # Check if any role has the permission
        role_ids = user_roles.values_list('role_id', flat=True)
        
        has_permission = Permission.objects.filter(
            code=permission_code,
            is_active=True,
            roles__id__in=role_ids,
            roles__is_active=True
        ).exists()
        
        return has_permission
        
    except Exception as e:
        logger.error(f"Error checking role permission: {e}", exc_info=True)
        return False


def _evaluate_policies(
    user,
    permission_code: str,
    obj=None,
    context: Optional[Dict[str, Any]] = None
) -> Tuple[bool, Optional[str]]:
    """
    Evaluate all policies for a permission.
    
    Args:
        user: User to check
        permission_code: Permission code
        obj: Object being accessed
        context: Additional context
        
    Returns:
        tuple: (allowed: bool, denial_reason: Optional[str])
    """
    try:
        return policy_registry.evaluate_policies(
            user, permission_code, obj, context
        )
    except PolicyEvaluationError as e:
        logger.error(f"Policy evaluation error: {e}", exc_info=True)
        # On policy error, deny access for safety
        return False, str(e)
    except Exception as e:
        logger.error(f"Unexpected error in policy evaluation: {e}", exc_info=True)
        return False, "Policy evaluation failed"


def _check_model_default(
    obj,
    user,
    permission_code: str,
    context: Optional[Dict[str, Any]] = None
) -> Optional[bool]:
    """
    Check model-level default permissions.
    
    This is a hook for models to provide default permission logic.
    Models can implement a method like:
    
        def check_default_permission(self, user, permission_code, context):
            return True/False
    
    Args:
        obj: Object to check
        user: User requesting permission
        permission_code: Permission code
        context: Additional context
        
    Returns:
        bool or None: True/False if model provides default, None otherwise
    """
    if hasattr(obj, 'check_default_permission'):
        try:
            return obj.check_default_permission(user, permission_code, context)
        except Exception as e:
            logger.error(
                f"Error checking model default permission: {e}",
                exc_info=True
            )
    
    return None


def has_permission(user, permission_code: str, obj=None, context=None) -> bool:
    """
    Alias for authorize() with a more Django-like name.
    
    Args:
        user: User requesting permission
        permission_code: Permission code
        obj: Object being accessed (optional)
        context: Additional context (optional)
        
    Returns:
        bool: True if authorized
    """
    return authorize(user, permission_code, obj, context)


def check_permission(user, permission_code: str, obj=None, context=None) -> bool:
    """
    Another alias for authorize().
    
    Args:
        user: User requesting permission
        permission_code: Permission code
        obj: Object being accessed (optional)
        context: Additional context (optional)
        
    Returns:
        bool: True if authorized
    """
    return authorize(user, permission_code, obj, context)


def get_user_permission_codes(user, include_roles: bool = True) -> set:
    """
    Get all permission codes for a user.
    
    Args:
        user: User to check
        include_roles: Whether to include role-based permissions
        
    Returns:
        set: Set of permission codes
    """
    if not user or not user.is_authenticated:
        return set()
    
    if user.is_superuser:
        # Superusers have all permissions
        return set(Permission.objects.filter(is_active=True).values_list('code', flat=True))
    
    permission_codes = set()
    
    # Add explicit allows (not denies)
    explicit_allows = UserPermission.objects.filter(
        user=user,
        allow=True,
        permission__is_active=True
    ).select_related('permission')
    
    permission_codes.update(
        perm.permission.code for perm in explicit_allows
    )
    
    # Add role-based permissions
    if include_roles:
        user_roles = UserRole.objects.filter(
            user=user,
            role__is_active=True
        ).prefetch_related('role__permissions')
        
        for user_role in user_roles:
            role_perms = user_role.role.permissions.filter(is_active=True)
            permission_codes.update(perm.code for perm in role_perms)
    
    # Remove explicit denies
    explicit_denies = UserPermission.objects.filter(
        user=user,
        allow=False,
        permission__is_active=True
    ).select_related('permission')
    
    for deny in explicit_denies:
        permission_codes.discard(deny.permission.code)
    
    return permission_codes

"""
Decorators for function-based views.

These decorators protect views by checking permissions before execution.
"""

from functools import wraps
from typing import Callable, Optional, Any
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest

from .engine import authorize


def require_permission(
    permission_code: str,
    obj_getter: Optional[Callable[[HttpRequest], Any]] = None,
    context_getter: Optional[Callable[[HttpRequest], dict]] = None,
    login_url: Optional[str] = None,
    raise_exception: bool = True
):
    """
    Decorator to require a permission for a function-based view.
    
    Args:
        permission_code: Permission code required (e.g., "courses.enroll")
        obj_getter: Optional callable to extract object from request
        context_getter: Optional callable to build context from request
        login_url: URL to redirect to if not authenticated
        raise_exception: If True, raise PermissionDenied; if False, redirect
        
    Example:
        @require_permission("courses.enroll")
        def enroll_view(request):
            # ... implementation
        
        @require_permission(
            "documents.edit",
            obj_getter=lambda req: get_object_or_404(Document, pk=req.GET['id'])
        )
        def edit_document(request):
            # ... implementation
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required(login_url=login_url)
        def wrapped_view(request, *args, **kwargs):
            # Get object if obj_getter provided
            obj = None
            if obj_getter:
                obj = obj_getter(request)
            
            # Get context if context_getter provided
            context = None
            if context_getter:
                context = context_getter(request)
            
            # Check permission
            if not authorize(request.user, permission_code, obj, context):
                if raise_exception:
                    raise PermissionDenied(
                        f"You do not have permission: {permission_code}"
                    )
                else:
                    from django.shortcuts import redirect
                    from django.conf import settings
                    return redirect(
                        getattr(settings, 'LOGIN_URL', '/accounts/login/')
                    )
            
            return view_func(request, *args, **kwargs)
        
        return wrapped_view
    
    return decorator


def require_any_permission(
    *permission_codes: str,
    obj_getter: Optional[Callable[[HttpRequest], Any]] = None,
    context_getter: Optional[Callable[[HttpRequest], dict]] = None,
    login_url: Optional[str] = None,
    raise_exception: bool = True
):
    """
    Decorator to require ANY of the specified permissions.
    
    User needs at least one of the permissions to access the view.
    
    Args:
        *permission_codes: Permission codes (user needs ANY of these)
        obj_getter: Optional callable to extract object from request
        context_getter: Optional callable to build context from request
        login_url: URL to redirect to if not authenticated
        raise_exception: If True, raise PermissionDenied; if False, redirect
        
    Example:
        @require_any_permission("courses.edit", "courses.admin")
        def manage_course(request):
            # ... implementation
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required(login_url=login_url)
        def wrapped_view(request, *args, **kwargs):
            # Get object if obj_getter provided
            obj = None
            if obj_getter:
                obj = obj_getter(request)
            
            # Get context if context_getter provided
            context = None
            if context_getter:
                context = context_getter(request)
            
            # Check if user has ANY of the permissions
            has_permission = any(
                authorize(request.user, perm_code, obj, context)
                for perm_code in permission_codes
            )
            
            if not has_permission:
                if raise_exception:
                    raise PermissionDenied(
                        f"You do not have any of the required permissions: "
                        f"{', '.join(permission_codes)}"
                    )
                else:
                    from django.shortcuts import redirect
                    from django.conf import settings
                    return redirect(
                        getattr(settings, 'LOGIN_URL', '/accounts/login/')
                    )
            
            return view_func(request, *args, **kwargs)
        
        return wrapped_view
    
    return decorator


def require_all_permissions(
    *permission_codes: str,
    obj_getter: Optional[Callable[[HttpRequest], Any]] = None,
    context_getter: Optional[Callable[[HttpRequest], dict]] = None,
    login_url: Optional[str] = None,
    raise_exception: bool = True
):
    """
    Decorator to require ALL of the specified permissions.
    
    User needs all permissions to access the view.
    
    Args:
        *permission_codes: Permission codes (user needs ALL of these)
        obj_getter: Optional callable to extract object from request
        context_getter: Optional callable to build context from request
        login_url: URL to redirect to if not authenticated
        raise_exception: If True, raise PermissionDenied; if False, redirect
        
    Example:
        @require_all_permissions("courses.edit", "courses.publish")
        def publish_course(request):
            # ... implementation
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required(login_url=login_url)
        def wrapped_view(request, *args, **kwargs):
            # Get object if obj_getter provided
            obj = None
            if obj_getter:
                obj = obj_getter(request)
            
            # Get context if context_getter provided
            context = None
            if context_getter:
                context = context_getter(request)
            
            # Check if user has ALL permissions
            missing_permissions = [
                perm_code
                for perm_code in permission_codes
                if not authorize(request.user, perm_code, obj, context)
            ]
            
            if missing_permissions:
                if raise_exception:
                    raise PermissionDenied(
                        f"You are missing required permissions: "
                        f"{', '.join(missing_permissions)}"
                    )
                else:
                    from django.shortcuts import redirect
                    from django.conf import settings
                    return redirect(
                        getattr(settings, 'LOGIN_URL', '/accounts/login/')
                    )
            
            return view_func(request, *args, **kwargs)
        
        return wrapped_view
    
    return decorator


def permission_required_or_403(permission_code: str, **kwargs):
    """
    Shortcut decorator that always raises PermissionDenied (403).
    
    Args:
        permission_code: Permission code required
        **kwargs: Additional arguments for require_permission
        
    Example:
        @permission_required_or_403("courses.delete")
        def delete_course(request, course_id):
            # ... implementation
    """
    kwargs['raise_exception'] = True
    return require_permission(permission_code, **kwargs)


def require_graphql_permission(permission_code: Optional[str], return_type = None):
    """
    Decorator for GraphQL mutations to check permissions.
    
    Args:
        permission_code: The permission code to check (e.g. 'properties.create'). 
                         If None, only checks authentication.
        return_type: The Graphene ObjectType class to return in case of error (e.g. PropertySingleDTO)
                     This class MUST have a 'response' field that accepts a standardized response object.
    
    Example:
        @require_graphql_permission('properties.create', PropertySingleDTO)
        def mutate(root, info, input):
            ...
    """
    def decorator(mutate_func):
        @wraps(mutate_func)
        def wrapper(root, info, *args, **kwargs):
            user = info.context.user
            
            # 1. Check Authentication
            if not user.is_authenticated:
                from tarxemo_django_graphene_utils import build_error_response
                return return_type(
                    data=None,
                    response=build_error_response("Authentication required", code=401)
                )
            
            # 2. Check Permission (if code provided)
            if permission_code:
                from .engine import authorize
                if not authorize(user, permission_code):
                    from tarxemo_django_graphene_utils import build_error_response
                    return return_type(
                        data=None,
                        response=build_error_response(f"Permission denied. Requires '{permission_code}'.", code=403)
                    )
                
            return mutate_func(root, info, *args, **kwargs)
        return wrapper
    return decorator

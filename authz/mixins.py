"""
Mixins for class-based views.

These mixins protect CBVs by checking permissions before dispatch.
"""

from typing import Optional, Any, Dict, List
from django.core.exceptions import PermissionDenied
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic.base import View

from .engine import authorize


class PermissionRequiredMixin(LoginRequiredMixin):
    """
    Mixin for class-based views that requires a permission.
    
    Attributes:
        permission_required: Permission code or list of codes (all required)
        permission_object: Object to check permission against (optional)
        permission_context: Context dict for permission check (optional)
        raise_exception: If True, raise PermissionDenied; if False, redirect
        
    Methods to override:
        get_permission_object(): Return object for permission check
        get_permission_context(): Return context dict for permission check
        get_permission_required(): Return permission code(s)
        handle_no_permission(): Custom handler for permission denial
        
    Example:
        class EnrollView(PermissionRequiredMixin, View):
            permission_required = "courses.enroll"
            
            def get_permission_object(self):
                return get_object_or_404(Course, pk=self.kwargs['pk'])
            
            def post(self, request, *args, **kwargs):
                # ... implementation
    """
    
    permission_required: str | List[str] = None
    permission_object: Any = None
    permission_context: Optional[Dict[str, Any]] = None
    raise_exception: bool = True
    
    def get_permission_required(self) -> List[str]:
        """
        Get the permission code(s) required for this view.
        
        Returns:
            List[str]: List of permission codes
        """
        if self.permission_required is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} must define permission_required "
                f"or override get_permission_required()"
            )
        
        if isinstance(self.permission_required, str):
            return [self.permission_required]
        return list(self.permission_required)
    
    def get_permission_object(self) -> Any:
        """
        Get the object to check permission against.
        
        Override this method to provide the object dynamically.
        
        Returns:
            Any: Object for permission check (or None)
        """
        return self.permission_object
    
    def get_permission_context(self) -> Optional[Dict[str, Any]]:
        """
        Get the context for permission check.
        
        Override this method to provide context dynamically.
        
        Returns:
            dict: Context for permission check (or None)
        """
        return self.permission_context
    
    def has_permission(self) -> bool:
        """
        Check if the user has the required permission(s).
        
        Returns:
            bool: True if user has all required permissions
        """
        perms = self.get_permission_required()
        obj = self.get_permission_object()
        context = self.get_permission_context()
        
        # User must have ALL permissions
        return all(
            authorize(self.request.user, perm, obj, context)
            for perm in perms
        )
    
    def handle_no_permission(self):
        """
        Handle the case when user doesn't have permission.
        
        Override this method for custom handling.
        
        Raises:
            PermissionDenied: If raise_exception is True
        """
        if self.raise_exception:
            perms = self.get_permission_required()
            raise PermissionDenied(
                f"You do not have the required permissions: {', '.join(perms)}"
            )
        return super().handle_no_permission()
    
    def dispatch(self, request, *args, **kwargs):
        """
        Check permission before dispatching the request.
        """
        if not self.has_permission():
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)


class MultiplePermissionsRequiredMixin(LoginRequiredMixin):
    """
    Mixin that supports complex permission requirements.
    
    Allows specifying permissions with 'any' and 'all' logic.
    
    Attributes:
        permissions_required: Dict with 'any' and/or 'all' keys
        
    Example:
        class ManageCourseView(MultiplePermissionsRequiredMixin, View):
            permissions_required = {
                'any': ['courses.edit', 'courses.admin'],
                'all': ['courses.view']
            }
            
            def get(self, request, *args, **kwargs):
                # User needs courses.view AND (courses.edit OR courses.admin)
                # ... implementation
    """
    
    permissions_required: Dict[str, List[str]] = None
    permission_object: Any = None
    permission_context: Optional[Dict[str, Any]] = None
    raise_exception: bool = True
    
    def get_permissions_required(self) -> Dict[str, List[str]]:
        """
        Get the permissions required for this view.
        
        Returns:
            dict: Dict with 'any' and/or 'all' keys
        """
        if self.permissions_required is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} must define permissions_required "
                f"or override get_permissions_required()"
            )
        return self.permissions_required
    
    def get_permission_object(self) -> Any:
        """Get the object to check permission against."""
        return self.permission_object
    
    def get_permission_context(self) -> Optional[Dict[str, Any]]:
        """Get the context for permission check."""
        return self.permission_context
    
    def has_permission(self) -> bool:
        """
        Check if the user has the required permissions.
        
        Returns:
            bool: True if user meets permission requirements
        """
        perms = self.get_permissions_required()
        obj = self.get_permission_object()
        context = self.get_permission_context()
        
        # Check 'all' permissions (must have ALL)
        if 'all' in perms:
            all_perms = perms['all']
            if not all(
                authorize(self.request.user, perm, obj, context)
                for perm in all_perms
            ):
                return False
        
        # Check 'any' permissions (must have at least ONE)
        if 'any' in perms:
            any_perms = perms['any']
            if not any(
                authorize(self.request.user, perm, obj, context)
                for perm in any_perms
            ):
                return False
        
        return True
    
    def handle_no_permission(self):
        """Handle the case when user doesn't have permission."""
        if self.raise_exception:
            perms = self.get_permissions_required()
            raise PermissionDenied(
                f"You do not have the required permissions: {perms}"
            )
        return super().handle_no_permission()
    
    def dispatch(self, request, *args, **kwargs):
        """Check permission before dispatching the request."""
        if not self.has_permission():
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)


class ObjectPermissionRequiredMixin(PermissionRequiredMixin):
    """
    Mixin that automatically gets the object for permission checks.
    
    This is useful for DetailView, UpdateView, DeleteView, etc.
    
    The object is retrieved via get_object() method.
    
    Example:
        class CourseDetailView(ObjectPermissionRequiredMixin, DetailView):
            model = Course
            permission_required = "courses.view"
            
            # get_object() is called automatically by DetailView
            # The mixin uses it for permission check
    """
    
    def get_permission_object(self) -> Any:
        """
        Get the object from the view's get_object() method.
        
        Returns:
            Any: The object being accessed
        """
        if hasattr(self, 'get_object'):
            return self.get_object()
        return super().get_permission_object()

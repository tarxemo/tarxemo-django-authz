"""
Django REST Framework integration (optional).

This module provides DRF permission classes that integrate with the
authorization framework. It's only loaded if DRF is installed.
"""

try:
    from rest_framework import permissions
    DRF_AVAILABLE = True
except ImportError:
    DRF_AVAILABLE = False
    permissions = None


if DRF_AVAILABLE:
    from authz.engine import authorize
    
    class AuthzPermission(permissions.BasePermission):
        """
        DRF permission class that uses the authorization framework.
        
        Set the permission_code attribute on your view or viewset.
        
        Example:
            class CourseViewSet(viewsets.ModelViewSet):
                permission_classes = [AuthzPermission]
                permission_code = "courses.view"
                
                def get_permission_code(self):
                    # Override for dynamic permission codes
                    if self.action == 'create':
                        return "courses.create"
                    elif self.action in ['update', 'partial_update']:
                        return "courses.edit"
                    elif self.action == 'destroy':
                        return "courses.delete"
                    return "courses.view"
        """
        
        message = "You do not have permission to perform this action."
        
        def has_permission(self, request, view):
            """
            Check if user has permission for the view.
            
            Args:
                request: DRF request object
                view: View being accessed
                
            Returns:
                bool: True if authorized
            """
            permission_code = self.get_permission_code(request, view)
            if not permission_code:
                # No permission code specified = deny by default
                return False
            
            context = self.get_permission_context(request, view)
            return authorize(request.user, permission_code, None, context)
        
        def has_object_permission(self, request, view, obj):
            """
            Check if user has permission for a specific object.
            
            Args:
                request: DRF request object
                view: View being accessed
                obj: Object being accessed
                
            Returns:
                bool: True if authorized
            """
            permission_code = self.get_permission_code(request, view, obj)
            if not permission_code:
                return False
            
            context = self.get_permission_context(request, view, obj)
            return authorize(request.user, permission_code, obj, context)
        
        def get_permission_code(self, request, view, obj=None):
            """
            Get the permission code for the request.
            
            Override this method or set permission_code on the view.
            
            Args:
                request: DRF request object
                view: View being accessed
                obj: Object being accessed (optional)
                
            Returns:
                str: Permission code
            """
            # Check if view has get_permission_code method
            if hasattr(view, 'get_permission_code'):
                return view.get_permission_code()
            
            # Check if view has permission_code attribute
            if hasattr(view, 'permission_code'):
                return view.permission_code
            
            return None
        
        def get_permission_context(self, request, view, obj=None):
            """
            Get the context for permission check.
            
            Override this method for custom context.
            
            Args:
                request: DRF request object
                view: View being accessed
                obj: Object being accessed (optional)
                
            Returns:
                dict: Context for permission check
            """
            context = {
                'request': request,
                'view': view,
                'action': getattr(view, 'action', None),
                'method': request.method,
            }
            
            # Check if view has get_permission_context method
            if hasattr(view, 'get_permission_context'):
                custom_context = view.get_permission_context()
                context.update(custom_context)
            
            return context
    
    
    class ActionBasedPermission(AuthzPermission):
        """
        DRF permission class with action-based permission codes.
        
        Define permission_codes dict on your viewset mapping actions to codes.
        
        Example:
            class CourseViewSet(viewsets.ModelViewSet):
                permission_classes = [ActionBasedPermission]
                permission_codes = {
                    'list': 'courses.view',
                    'retrieve': 'courses.view',
                    'create': 'courses.create',
                    'update': 'courses.edit',
                    'partial_update': 'courses.edit',
                    'destroy': 'courses.delete',
                }
        """
        
        def get_permission_code(self, request, view, obj=None):
            """
            Get permission code based on the action.
            
            Args:
                request: DRF request object
                view: View being accessed
                obj: Object being accessed (optional)
                
            Returns:
                str: Permission code for the action
            """
            # Check if view has permission_codes dict
            if hasattr(view, 'permission_codes'):
                action = getattr(view, 'action', None)
                if action and action in view.permission_codes:
                    return view.permission_codes[action]
            
            # Fall back to parent implementation
            return super().get_permission_code(request, view, obj)

else:
    # DRF not available - provide stub classes
    class AuthzPermission:
        """Stub class when DRF is not installed."""
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "Django REST Framework is not installed. "
                "Install it with: pip install djangorestframework"
            )
    
    class ActionBasedPermission(AuthzPermission):
        """Stub class when DRF is not installed."""
        pass

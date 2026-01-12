"""
Abstract base models for permission-aware resources.

These models provide permission metadata only - they do NOT contain
authorization logic. All authorization decisions are made by the
authorization engine.
"""

from django.db import models
from typing import Optional, Dict, Any


class PermissionAwareMixin(models.Model):
    """
    Abstract mixin that provides permission metadata for business models.
    
    Business models can inherit from this to expose permission-related
    metadata to the authorization engine without embedding authorization
    logic in the model itself.
    
    Example:
        class Course(PermissionAwareMixin, models.Model):
            title = models.CharField(max_length=200)
            instructor = models.ForeignKey(User, on_delete=models.CASCADE)
            
            def get_permission_namespace(self):
                return "courses"
            
            def get_owner(self):
                return self.instructor
    """
    
    class Meta:
        abstract = True
    
    def get_permission_namespace(self) -> str:
        """
        Return the permission namespace for this resource.
        
        The namespace is typically the app name or resource category.
        For example: "courses", "orders", "documents"
        
        Returns:
            str: Permission namespace
        """
        # Default: use app label
        return self._meta.app_label
    
    def get_resource_name(self) -> str:
        """
        Return the resource name for this model.
        
        This is used to construct permission codes like:
        "{namespace}.{action}" or "{namespace}.{resource}.{action}"
        
        Returns:
            str: Resource name (typically model name in lowercase)
        """
        return self._meta.model_name
    
    def get_owner(self) -> Optional[Any]:
        """
        Return the owner of this resource, if applicable.
        
        This is used by policies that need to check ownership.
        For example, "only the owner can edit this resource".
        
        Returns:
            User instance or None if no owner concept applies
        """
        # Default: no owner
        # Override in subclasses if ownership applies
        return None
    
    def get_permission_context(self) -> Dict[str, Any]:
        """
        Return additional context for policy evaluation.
        
        Policies can use this context to make dynamic decisions.
        For example, a course might return {"academic_year": 2024}
        
        Returns:
            dict: Context dictionary for policy evaluation
        """
        return {
            'resource_type': self.get_resource_name(),
            'namespace': self.get_permission_namespace(),
            'pk': self.pk,
        }
    
    def has_permission_metadata(self) -> bool:
        """
        Check if this model provides permission metadata.
        
        This is a marker method that the authorization engine can use
        to detect permission-aware models.
        
        Returns:
            bool: Always True for PermissionAwareMixin
        """
        return True


class OwnedResourceMixin(PermissionAwareMixin):
    """
    Abstract mixin for resources that have an owner.
    
    This extends PermissionAwareMixin with a standard owner field.
    Use this when your resource has a clear owner concept.
    
    Example:
        class Document(OwnedResourceMixin, models.Model):
            title = models.CharField(max_length=200)
            content = models.TextField()
            
            # owner field is inherited from OwnedResourceMixin
    """
    
    owner = models.ForeignKey(
        'auth.User',
        on_delete=models.CASCADE,
        related_name='%(app_label)s_%(class)s_owned',
        help_text="The user who owns this resource"
    )
    
    class Meta:
        abstract = True
    
    def get_owner(self) -> Any:
        """
        Return the owner of this resource.
        
        Returns:
            User: The owner user instance
        """
        return self.owner

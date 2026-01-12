"""
Core RBAC models for the authorization framework.

These models implement Role-Based Access Control (RBAC) with support for:
- Permissions: Fine-grained permission codes
- Roles: Collections of permissions
- UserRole: Many-to-many relationship between users and roles
- UserPermission: Direct user permission overrides (allow/deny)
"""

from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class Permission(models.Model):
    """
    Represents a single permission in the system.
    
    Permissions are identified by a unique code (e.g., "courses.enroll").
    They can be assigned to roles or directly to users.
    """
    
    code = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text=_("Unique permission code (e.g., 'courses.enroll')")
    )
    
    description = models.TextField(
        blank=True,
        help_text=_("Human-readable description of what this permission allows")
    )
    
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text=_("Whether this permission is currently active")
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['code']
        verbose_name = _("Permission")
        verbose_name_plural = _("Permissions")
    
    def __str__(self):
        return self.code
    
    def clean(self):
        """Validate permission code format."""
        if not self.code:
            raise ValidationError(_("Permission code cannot be empty"))
        
        # Basic validation: should contain at least one dot
        if '.' not in self.code:
            raise ValidationError(
                _("Permission code should follow the format 'namespace.action' (e.g., 'courses.enroll')")
            )
    
    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)


class Role(models.Model):
    """
    Represents a role that groups multiple permissions.
    
    Roles can be assigned to users, giving them all permissions
    associated with that role.
    """
    
    name = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text=_("Unique role name (e.g., 'Student', 'Instructor')")
    )
    
    description = models.TextField(
        blank=True,
        help_text=_("Description of this role and its purpose")
    )
    
    permissions = models.ManyToManyField(
        Permission,
        related_name='roles',
        blank=True,
        help_text=_("Permissions granted by this role")
    )
    
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        help_text=_("Whether this role is currently active")
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
        verbose_name = _("Role")
        verbose_name_plural = _("Roles")
    
    def __str__(self):
        return self.name
    
    def get_permission_codes(self):
        """
        Get all permission codes for this role.
        
        Returns:
            QuerySet: Permission codes as strings
        """
        return self.permissions.filter(is_active=True).values_list('code', flat=True)
    
    def add_permission(self, permission_code):
        """
        Add a permission to this role by code.
        
        Args:
            permission_code (str): Permission code to add
            
        Raises:
            Permission.DoesNotExist: If permission doesn't exist
        """
        permission = Permission.objects.get(code=permission_code)
        self.permissions.add(permission)
    
    def remove_permission(self, permission_code):
        """
        Remove a permission from this role by code.
        
        Args:
            permission_code (str): Permission code to remove
        """
        try:
            permission = Permission.objects.get(code=permission_code)
            self.permissions.remove(permission)
        except Permission.DoesNotExist:
            pass


class UserRole(models.Model):
    """
    Associates users with roles.
    
    This is a many-to-many relationship with audit fields to track
    who assigned the role and when.
    """
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='user_roles',
        help_text=_("User to whom this role is assigned")
    )
    
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name='user_assignments',
        help_text=_("Role assigned to the user")
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='role_assignments_created',
        help_text=_("User who assigned this role")
    )
    
    class Meta:
        unique_together = [['user', 'role']]
        ordering = ['-created_at']
        verbose_name = _("User Role")
        verbose_name_plural = _("User Roles")
        indexes = [
            models.Index(fields=['user', 'role']),
        ]
    
    def __str__(self):
        return f"{self.user} - {self.role}"
    
    def clean(self):
        """Validate that the role is active."""
        if self.role and not self.role.is_active:
            raise ValidationError(_("Cannot assign an inactive role"))
    
    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)


class UserPermission(models.Model):
    """
    Direct user permission overrides.
    
    This allows granting or denying specific permissions to individual users,
    overriding their role-based permissions.
    
    The 'allow' field determines whether this is a grant (True) or deny (False).
    Explicit denies always take precedence in the authorization engine.
    """
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='authz_permissions',  # Changed from user_permissions to avoid clash
        help_text=_("User to whom this permission override applies")
    )
    
    permission = models.ForeignKey(
        Permission,
        on_delete=models.CASCADE,
        related_name='user_overrides',
        help_text=_("Permission being granted or denied")
    )
    
    allow = models.BooleanField(
        default=True,
        help_text=_("True = explicitly allow, False = explicitly deny")
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='permission_overrides_created',
        help_text=_("User who created this permission override")
    )
    
    class Meta:
        unique_together = [['user', 'permission']]
        ordering = ['-created_at']
        verbose_name = _("User Permission")
        verbose_name_plural = _("User Permissions")
        indexes = [
            models.Index(fields=['user', 'permission']),
            models.Index(fields=['user', 'allow']),
        ]
    
    def __str__(self):
        action = "ALLOW" if self.allow else "DENY"
        return f"{self.user} - {self.permission.code} ({action})"
    
    def clean(self):
        """Validate that the permission is active."""
        if self.permission and not self.permission.is_active:
            raise ValidationError(_("Cannot assign an inactive permission"))
    
    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

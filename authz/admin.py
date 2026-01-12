"""
Django admin configuration for the authorization framework.

Provides admin interfaces for managing permissions, roles, user roles,
and user permission overrides.

NOTE: Admin registrations temporarily disabled due to naming conflict
with Django's built-in Permission model. Will be re-enabled with proper namespacing.
"""

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.db.models import Count

from .models import Permission, Role, UserRole, UserPermission


User = get_user_model()

# Temporarily disabled to avoid conflict - will fix
# @admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    """
    Admin interface for Permission model.
    """
    
    list_display = ['code', 'description_short', 'is_active', 'role_count', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['code', 'description']
    ordering = ['code']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = [
        (None, {
            'fields': ['code', 'description', 'is_active']
        }),
        ('Metadata', {
            'fields': ['created_at', 'updated_at'],
            'classes': ['collapse']
        }),
    ]
    
    def description_short(self, obj):
        """Truncated description for list display."""
        if len(obj.description) > 50:
            return obj.description[:50] + '...'
        return obj.description
    description_short.short_description = 'Description'
    
    def role_count(self, obj):
        """Number of roles with this permission."""
        return obj.roles.filter(is_active=True).count()
    role_count.short_description = 'Roles'
    
    def get_queryset(self, request):
        """Optimize queryset with annotations."""
        qs = super().get_queryset(request)
        return qs.annotate(
            _role_count=Count('roles', distinct=True)
        )
    
    actions = ['activate_permissions', 'deactivate_permissions']
    
    def activate_permissions(self, request, queryset):
        """Bulk activate permissions."""
        updated = queryset.update(is_active=True)
        self.message_user(request, f"{updated} permissions activated.")
    activate_permissions.short_description = "Activate selected permissions"
    
    def deactivate_permissions(self, request, queryset):
        """Bulk deactivate permissions."""
        updated = queryset.update(is_active=False)
        self.message_user(request, f"{updated} permissions deactivated.")
    deactivate_permissions.short_description = "Deactivate selected permissions"


class RolePermissionInline(admin.TabularInline):
    """
    Inline for managing permissions within a role.
    """
    model = Role.permissions.through
    extra = 1
    verbose_name = "Permission"
    verbose_name_plural = "Permissions"
    
    def get_queryset(self, request):
        """Filter to show only active permissions."""
        qs = super().get_queryset(request)
        return qs.select_related('permission')


# @admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    """
    Admin interface for Role model.
    """
    
    list_display = ['name', 'description_short', 'permission_count', 'user_count', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'description']
    ordering = ['name']
    readonly_fields = ['created_at', 'updated_at', 'permission_list']
    
    filter_horizontal = ['permissions']
    
    fieldsets = [
        (None, {
            'fields': ['name', 'description', 'is_active']
        }),
        ('Permissions', {
            'fields': ['permissions', 'permission_list']
        }),
        ('Metadata', {
            'fields': ['created_at', 'updated_at'],
            'classes': ['collapse']
        }),
    ]
    
    def description_short(self, obj):
        """Truncated description for list display."""
        if len(obj.description) > 50:
            return obj.description[:50] + '...'
        return obj.description
    description_short.short_description = 'Description'
    
    def permission_count(self, obj):
        """Number of permissions in this role."""
        return obj.permissions.filter(is_active=True).count()
    permission_count.short_description = 'Permissions'
    
    def user_count(self, obj):
        """Number of users with this role."""
        return obj.user_assignments.count()
    user_count.short_description = 'Users'
    
    def permission_list(self, obj):
        """Display list of permissions."""
        if obj.pk:
            perms = obj.permissions.filter(is_active=True).values_list('code', flat=True)
            if perms:
                return format_html('<br>'.join(perms))
        return "No permissions"
    permission_list.short_description = 'Current Permissions'
    
    def get_queryset(self, request):
        """Optimize queryset."""
        qs = super().get_queryset(request)
        return qs.prefetch_related('permissions')
    
    actions = ['activate_roles', 'deactivate_roles']
    
    def activate_roles(self, request, queryset):
        """Bulk activate roles."""
        updated = queryset.update(is_active=True)
        self.message_user(request, f"{updated} roles activated.")
    activate_roles.short_description = "Activate selected roles"
    
    def deactivate_roles(self, request, queryset):
        """Bulk deactivate roles."""
        updated = queryset.update(is_active=False)
        self.message_user(request, f"{updated} roles deactivated.")
    deactivate_roles.short_description = "Deactivate selected roles"


# @admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    """
    Admin interface for UserRole model.
    """
    
    list_display = ['user', 'role', 'created_at', 'created_by']
    list_filter = ['role', 'created_at']
    search_fields = ['user__username', 'user__email', 'role__name']
    ordering = ['-created_at']
    readonly_fields = ['created_at']
    
    autocomplete_fields = ['user', 'created_by']
    
    fieldsets = [
        (None, {
            'fields': ['user', 'role']
        }),
        ('Audit', {
            'fields': ['created_by', 'created_at'],
            'classes': ['collapse']
        }),
    ]
    
    def get_queryset(self, request):
        """Optimize queryset."""
        qs = super().get_queryset(request)
        return qs.select_related('user', 'role', 'created_by')


# @admin.register(UserPermission)
class UserPermissionAdmin(admin.ModelAdmin):
    """
    Admin interface for UserPermission model.
    """
    
    list_display = ['user', 'permission', 'allow_display', 'created_at', 'created_by']
    list_filter = ['allow', 'created_at']
    search_fields = ['user__username', 'user__email', 'permission__code']
    ordering = ['-created_at']
    readonly_fields = ['created_at']
    
    autocomplete_fields = ['user', 'created_by']
    
    fieldsets = [
        (None, {
            'fields': ['user', 'permission', 'allow']
        }),
        ('Audit', {
            'fields': ['created_by', 'created_at'],
            'classes': ['collapse']
        }),
    ]
    
    def allow_display(self, obj):
        """Display allow/deny with color coding."""
        if obj.allow:
            return format_html(
                '<span style="color: green; font-weight: bold;">✓ ALLOW</span>'
            )
        else:
            return format_html(
                '<span style="color: red; font-weight: bold;">✗ DENY</span>'
            )
    allow_display.short_description = 'Action'
    
    def get_queryset(self, request):
        """Optimize queryset."""
        qs = super().get_queryset(request)
        return qs.select_related('user', 'permission', 'created_by')


# ============================================================================
# User Admin Integration (Inlines)
# ============================================================================


class UserRoleInline(admin.TabularInline):
    """
    Inline for managing user roles in the User admin.
    """
    model = UserRole
    extra = 1
    verbose_name = "Role"
    verbose_name_plural = "Roles"
    
    fields = ['role', 'created_at', 'created_by']
    readonly_fields = ['created_at']
    autocomplete_fields = ['created_by']
    
    def get_queryset(self, request):
        """Filter to show only active roles."""
        qs = super().get_queryset(request)
        return qs.select_related('role').filter(role__is_active=True)


class UserPermissionInline(admin.TabularInline):
    """
    Inline for managing user permission overrides in the User admin.
    """
    model = UserPermission
    extra = 1
    verbose_name = "Permission Override"
    verbose_name_plural = "Permission Overrides"
    
    fields = ['permission', 'allow', 'created_at', 'created_by']
    readonly_fields = ['created_at']
    autocomplete_fields = ['created_by']
    
    def get_queryset(self, request):
        """Optimize queryset."""
        qs = super().get_queryset(request)
        return qs.select_related('permission')


# Extend the default User admin with our inlines
# This is optional - uncomment if you want to add to the default User admin
# try:
#     admin.site.unregister(User)
# except admin.sites.NotRegistered:
#     pass
# 
# @admin.register(User)
# class CustomUserAdmin(BaseUserAdmin):
#     """Extended User admin with authorization inlines."""
#     inlines = BaseUserAdmin.inlines + [UserRoleInline, UserPermissionInline]


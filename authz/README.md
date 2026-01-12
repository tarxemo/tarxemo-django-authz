# Django Authorization Framework (`authz`)

A comprehensive, reusable Django authorization framework supporting both Role-Based Access Control (RBAC) and Policy-Based Access Control (PBAC).

## Features

- ✅ **RBAC**: Roles, permissions, user assignments with audit trails
- ✅ **PBAC**: Custom policy system for dynamic business rules
- ✅ **Deny-First Security**: Explicit denies override all allows
- ✅ **Enforcement Tools**: Decorators, mixins, template tags, DRF integration
- ✅ **Django Admin**: Full admin interfaces for managing permissions and roles
- ✅ **Separation of Concerns**: Authorization logic separate from business models
- ✅ **Production-Ready**: Comprehensive validation, error handling, optimized queries
- ✅ **Well-Tested**: 28 tests covering all major functionality

## Quick Start

### 1. Installation

The app is already installed in your project. Just ensure it's in `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ...
    'authz',
]
```

### 2. Run Migrations

```bash
python manage.py migrate
```

### 3. Create Permissions

```python
from authz.models import Permission

Permission.objects.create(
    code="articles.create",
    description="Create articles"
)
```

### 4. Create Roles

```python
from authz.models import Role

author_role = Role.objects.create(name="Author")
author_role.add_permission("articles.create")
```

### 5. Assign Roles

```python
from authz.services import assign_role

assign_role(user, "Author")
```

### 6. Check Permissions

```python
from authz.engine import authorize

if authorize(user, "articles.create"):
    # User can create articles
    pass
```

## Usage

### In Views

**Function-Based Views:**
```python
from authz.decorators import require_permission

@require_permission("articles.create")
def create_article(request):
    # ... implementation
    pass
```

**Class-Based Views:**
```python
from authz.mixins import PermissionRequiredMixin

class ArticleCreateView(PermissionRequiredMixin, CreateView):
    model = Article
    permission_required = "articles.create"
```

### In Templates

```django
{% load authz_tags %}

{% if_has_permission 'articles.edit' article %}
    <a href="{% url 'edit_article' article.pk %}">Edit</a>
{% endif_has_permission %}
```

### Custom Policies

```python
from authz.policies import BasePolicy, register_policy

@register_policy
class OwnerOnlyPolicy(BasePolicy):
    permission_code = "articles.edit"
    
    def allows(self, user, obj=None, context=None):
        return obj and obj.author == user
    
    def get_denial_reason(self, user, obj=None, context=None):
        return "Only the author can edit this article"
```

### Django REST Framework

```python
from authz.drf_permissions import AuthzPermission

class ArticleViewSet(viewsets.ModelViewSet):
    permission_classes = [AuthzPermission]
    permission_code = "articles.view"
```

## Architecture

### Authorization Flow

1. ❌ Anonymous users → DENY
2. ✅ Superusers → ALLOW (bypass all checks)
3. ❌ Explicit user deny → DENY
4. ✅ Explicit user allow → ALLOW
5. ✅ Role-based permission → ALLOW (if policies pass)
6. ✅ Model defaults → ALLOW/DENY (if policies pass)
7. ❌ Default → DENY

### Models

- **Permission**: Fine-grained permission codes (e.g., "articles.create")
- **Role**: Collections of permissions
- **UserRole**: User-role assignments with audit fields
- **UserPermission**: Direct user permission overrides (allow/deny)

### Policies

Policies implement custom business rules that constrain RBAC grants. They are:
- Stateless and reusable
- Evaluated after RBAC checks
- Can only deny or allow what RBAC grants

## API Reference

### Core Functions

```python
from authz.engine import authorize

# Check permission
authorize(user, permission_code, obj=None, context=None) -> bool
```

### Service Layer

```python
from authz.services import (
    assign_role, revoke_role, get_user_roles,
    grant_permission, deny_permission, revoke_user_permission,
    get_permission_matrix, get_users_with_permission
)

# Role management
assign_role(user, role_name, created_by=None)
revoke_role(user, role_name)
get_user_roles(user)

# Permission management
grant_permission(user, permission_code, created_by=None)
deny_permission(user, permission_code, created_by=None)
revoke_user_permission(user, permission_code)

# Queries
get_permission_matrix(user)
get_users_with_permission(permission_code)
```

## Testing

Run the test suite:

```bash
python manage.py test authz
```

All 28 tests should pass.

## Admin Interface

Navigate to `/admin/authz/` to manage:
- Permissions
- Roles
- User role assignments
- User permission overrides

## Best Practices

1. **Permission Naming**: Use `namespace.action` format (e.g., "articles.create", "courses.enroll")
2. **Roles**: Create roles for common user types (e.g., "Author", "Editor", "Admin")
3. **Policies**: Use for complex business rules that can't be expressed in RBAC
4. **Explicit Denies**: Use sparingly, only when you need to override role permissions
5. **Audit**: Always pass `created_by` when assigning roles/permissions programmatically

## License

This authorization framework is part of your Django project.

## Support

For issues or questions, refer to the implementation plan and walkthrough documentation in the `brain/` directory.

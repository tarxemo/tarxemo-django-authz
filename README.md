# tarxemo-django-authz

A comprehensive, production-ready Django authorization framework supporting both **Role-Based Access Control (RBAC)** and **Policy-Based Access Control (PBAC)**. This library provides a complete solution for managing permissions, roles, and access control in your Django applications.

## Table of Contents

- [Features](#features)
- [When to Use This Library](#when-to-use-this-library)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Core Concepts](#core-concepts)
- [Complete API Reference](#complete-api-reference)
- [GraphQL API](#graphql-api)
- [Usage Examples](#usage-examples)
- [Django Admin](#django-admin)
- [Best Practices](#best-practices)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

✅ **Role-Based Access Control (RBAC)**
- Create roles that group multiple permissions
- Assign roles to users with full audit trails
- Flexible role management with active/inactive states

✅ **Policy-Based Access Control (PBAC)**
- Define custom policies for complex business rules
- Policies work alongside RBAC for fine-grained control
- Support for object-level and context-aware permissions

✅ **Deny-First Security Model**
- Explicit denies always override allows
- Secure by default - unauthorized access is denied
- Superuser bypass for administrative access

✅ **Multiple Integration Points**
- Function decorators for function-based views
- Mixins for class-based views
- Django REST Framework permission classes
- Template tags for conditional rendering
- Direct API calls for custom logic

✅ **GraphQL Support**
- Complete GraphQL API for managing permissions and roles
- Queries for listing and retrieving authorization data
- Mutations for creating, updating, and assigning permissions/roles

✅ **Django Admin Integration**
- Full admin interfaces for all models
- Search, filter, and bulk actions
- Read-only fields for security

✅ **Production-Ready**
- Comprehensive validation and error handling
- Optimized database queries with proper indexing
- Extensive test coverage
- Detailed logging for debugging

---

## When to Use This Library

Use **tarxemo-django-authz** when you need:

- **Fine-grained permissions** beyond Django's built-in permission system
- **Role-based access control** to group permissions logically
- **Custom authorization logic** that depends on object state or context
- **Separation of concerns** between business logic and authorization
- **GraphQL API** for managing permissions from frontend applications
- **Audit trails** to track who assigned permissions and when
- **Multi-tenant applications** with complex permission requirements

### RBAC vs PBAC

**RBAC (Role-Based Access Control):**
- Users are assigned roles (e.g., "Editor", "Manager")
- Roles contain collections of permissions
- Best for: Organizational hierarchies, job functions

**PBAC (Policy-Based Access Control):**
- Custom Python code evaluates permissions
- Can check object ownership, business rules, time-based access, etc.
- Best for: Resource ownership, dynamic rules, complex conditions

This library lets you use **both together** - RBAC for general permissions, PBAC for special cases.

---

## Installation

### From PyPI (Recommended)

```bash
pip install tarxemo-django-authz
```

### From GitHub (Development)

```bash
pip install git+https://github.com/tarxemo/tarxemo-django-authz.git
```

### Dependencies

This library requires:
- **Django** >= 3.2
- **graphene-django** >= 3.0 (for GraphQL support)
- **tarxemo-django-graphene-utils** >= 0.1.2 (for GraphQL utilities)

Optional:
- **djangorestframework** >= 3.12 (for DRF integration)

Install with DRF support:
```bash
pip install tarxemo-django-authz[drf]
```

---

## Quick Start

Follow these steps to get started with tarxemo-django-authz in just a few minutes.

### Step 1: Add to INSTALLED_APPS

Add `authz` and its dependency to your Django `settings.py`:

```python
INSTALLED_APPS = [
    # ... your other apps
    'tarxemo_django_graphene_utils',  # Required dependency
    'authz',
]
```

### Step 2: Run Migrations

Create the necessary database tables:

```bash
python manage.py migrate authz
```

This creates four tables:
- `authz_permission` - Stores permission definitions
- `authz_role` - Stores role definitions
- `authz_userrole` - Links users to roles
- `authz_userpermission` - Stores explicit user permission overrides

### Step 3: Create Your First Permission

```python
from authz.models import Permission

# Create a permission for creating articles
Permission.objects.create(
    code="articles.create",
    description="Allows user to create new articles"
)

# Create more permissions
Permission.objects.create(
    code="articles.edit",
    description="Allows user to edit existing articles"
)

Permission.objects.create(
    code="articles.delete",
    description="Allows user to delete articles"
)
```

**Permission Naming Convention:** Use the format `namespace.action` (e.g., `articles.create`, `users.view`, `reports.export`)

### Step 4: Create a Role

```python
from authz.models import Role

# Create an "Author" role
author_role = Role.objects.create(
    name="Author",
    description="Can create and edit their own articles"
)

# Add permissions to the role
author_role.add_permission("articles.create")
author_role.add_permission("articles.edit")
```

### Step 5: Assign Role to a User

```python
from authz.services import assign_role
from django.contrib.auth import get_user_model

User = get_user_model()
user = User.objects.get(username="john")

# Assign the Author role
assign_role(user, "Author", created_by=request.user)
```

### Step 6: Check Permissions

Now you can check if a user has permission:

```python
from authz.engine import authorize

# Check if user can create articles
if authorize(user, "articles.create"):
    # User has permission - allow action
    article = Article.objects.create(...)
else:
    # User doesn't have permission - deny action
    return HttpResponseForbidden("You don't have permission to create articles")
```

**That's it!** You now have a working authorization system. Continue reading for advanced features and complete API documentation.

---

## Configuration

### Required Settings

Add `authz` to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ...
    'tarxemo_django_graphene_utils',
    'authz',
]
```

### Optional Settings

Currently, `authz` works out of the box with no additional configuration. All settings use Django defaults.

### Authentication Model Compatibility

The library works with any Django authentication model:
- Django's default `User` model
- Custom user models (via `AUTH_USER_MODEL`)
- Third-party authentication packages

The library uses `settings.AUTH_USER_MODEL` to reference your user model, so it automatically adapts to your setup.

---

## Core Concepts

### Models

#### Permission

Represents a single permission in your system.

**Fields:**
- `code` (CharField, unique) - Permission identifier (e.g., "articles.create")
- `description` (TextField) - Human-readable description
- `is_active` (BooleanField) - Whether permission is currently active
- `created_at`, `updated_at` - Timestamps

**Methods:**
- `__str__()` - Returns the permission code

**Example:**
```python
permission = Permission.objects.create(
    code="courses.enroll",
    description="Allows students to enroll in courses"
)
```

#### Role

A collection of permissions that can be assigned to users.

**Fields:**
- `name` (CharField, unique) - Role name (e.g., "Student", "Instructor")
- `description` (TextField) - Role description
- `permissions` (ManyToManyField) - Permissions included in this role
- `is_active` (BooleanField) - Whether role is currently active
- `created_at`, `updated_at` - Timestamps

**Methods:**
- `get_permission_codes()` - Returns QuerySet of permission codes
- `add_permission(permission_code)` - Add a permission to this role
- `remove_permission(permission_code)` - Remove a permission from this role

**Example:**
```python
role = Role.objects.create(
    name="Student",
    description="Regular student with basic access"
)
role.add_permission("courses.view")
role.add_permission("courses.enroll")
```

#### UserRole

Links users to roles with audit information.

**Fields:**
- `user` (ForeignKey) - The user
- `role` (ForeignKey) - The role
- `created_at` (DateTimeField) - When role was assigned
- `created_by` (ForeignKey, nullable) - Who assigned the role

**Constraints:**
- Unique together: (user, role) - A user can't have the same role twice

**Example:**
```python
from authz.services import assign_role

assign_role(user, "Student", created_by=admin_user)
```

#### UserPermission

Direct permission overrides for individual users.

**Fields:**
- `user` (ForeignKey) - The user
- `permission` (ForeignKey) - The permission
- `allow` (BooleanField) - True = grant, False = deny
- `created_at` (DateTimeField) - When override was created
- `created_by` (ForeignKey, nullable) - Who created the override

**Constraints:**
- Unique together: (user, permission) - One override per user per permission

**Example:**
```python
from authz.services import grant_permission, deny_permission

# Explicitly grant a permission
grant_permission(user, "articles.delete", created_by=admin_user)

# Explicitly deny a permission (overrides role permissions)
deny_permission(user, "courses.grade", created_by=admin_user)
```

### Authorization Flow

When you call `authorize(user, permission_code)`, the system evaluates permissions in this order:

1. **❌ Anonymous Users** → DENY (unless policies explicitly allow)
2. **✅ Superusers** → ALLOW (bypass all checks)
3. **❌ Explicit User Deny** → DENY (UserPermission with allow=False)
4. **✅ Explicit User Allow** → ALLOW (UserPermission with allow=True)
5. **✅ Role-Based Permission** → ALLOW (if user has role with permission)
6. **✅ Model Defaults** → ALLOW/DENY (if object implements default permission logic)
7. **❌ Default** → DENY (secure by default)

**At each step**, policies are evaluated. If any policy denies, the request is denied regardless of RBAC grants.

### Policies

Policies are Python classes that implement custom authorization logic. They work **alongside** RBAC to add additional constraints.

**Key Points:**
- Policies are evaluated **after** RBAC checks
- Policies can only **deny** what RBAC grants (they can't grant new permissions)
- Multiple policies can be registered for the same permission
- If any policy denies, the request is denied

**Example Policy:**
```python
from authz.policies import BasePolicy, register_policy

@register_policy
class OwnerOnlyPolicy(BasePolicy):
    permission_code = "articles.edit"
    
    def allows(self, user, obj=None, context=None):
        """Only allow if user owns the article"""
        if obj and hasattr(obj, 'author'):
            return obj.author == user
        return False
    
    def get_denial_reason(self, user, obj=None, context=None):
        return "You can only edit your own articles"
```

Now, even if a user has the `articles.edit` permission via a role, they can only edit articles they own.

---

## Complete API Reference

### Engine Functions

These are the core functions for checking permissions.

#### `authorize(user, permission_code, obj=None, context=None)`

**Main authorization function.** Checks if a user has permission to perform an action.

**Parameters:**
- `user` - User instance to check
- `permission_code` (str) - Permission code (e.g., "articles.create")
- `obj` (optional) - Object being accessed (for object-level permissions)
- `context` (dict, optional) - Additional context for policy evaluation

**Returns:** `bool` - True if authorized, False otherwise

**Example:**
```python
from authz.engine import authorize

# Simple permission check
if authorize(user, "articles.create"):
    article = Article.objects.create(...)

# Object-level permission check
article = Article.objects.get(pk=1)
if authorize(user, "articles.edit", obj=article):
    article.title = "New Title"
    article.save()

# With context
if authorize(user, "reports.export", context={"format": "pdf"}):
    generate_pdf_report()
```

#### `has_permission(user, permission_code, obj=None, context=None)`

Alias for `authorize()` with a more Django-like name.

**Example:**
```python
from authz.engine import has_permission

if has_permission(user, "courses.enroll"):
    enrollment = Enrollment.objects.create(...)
```

#### `check_permission(user, permission_code, obj=None, context=None)`

Another alias for `authorize()`.

#### `get_user_permission_codes(user, include_roles=True)`

Get all permission codes for a user.

**Parameters:**
- `user` - User instance
- `include_roles` (bool) - Whether to include role-based permissions (default: True)

**Returns:** `set` - Set of permission code strings

**Example:**
```python
from authz.engine import get_user_permission_codes

codes = get_user_permission_codes(user)
print(codes)
# {'articles.create', 'articles.edit', 'courses.view', ...}

# Only explicit permissions (no roles)
explicit_codes = get_user_permission_codes(user, include_roles=False)
```

---

### Service Functions

High-level functions for managing roles and permissions.

#### Role Management

##### `assign_role(user, role_name, created_by=None)`

Assign a role to a user.

**Parameters:**
- `user` - User instance
- `role_name` (str) - Name of the role
- `created_by` (User, optional) - User who is assigning the role (for audit trail)

**Returns:** `UserRole` instance

**Raises:** `Role.DoesNotExist` if role doesn't exist

**Example:**
```python
from authz.services import assign_role

user_role = assign_role(user, "Editor", created_by=request.user)
```

##### `revoke_role(user, role_name)`

Remove a role from a user.

**Parameters:**
- `user` - User instance
- `role_name` (str) - Name of the role

**Returns:** `bool` - True if role was revoked, False if user didn't have the role

**Example:**
```python
from authz.services import revoke_role

success = revoke_role(user, "Editor")
if success:
    print("Role revoked")
```

##### `get_user_roles(user)`

Get all roles assigned to a user.

**Parameters:**
- `user` - User instance

**Returns:** `List[Role]` - List of Role objects

**Example:**
```python
from authz.services import get_user_roles

roles = get_user_roles(user)
for role in roles:
    print(f"User has role: {role.name}")
```

##### `get_user_role_names(user)`

Get role names as strings.

**Parameters:**
- `user` - User instance

**Returns:** `List[str]` - List of role names

**Example:**
```python
from authz.services import get_user_role_names

role_names = get_user_role_names(user)
print(role_names)  # ['Student', 'TA']
```

##### `user_has_role(user, role_name)`

Check if user has a specific role.

**Parameters:**
- `user` - User instance
- `role_name` (str) - Role name to check

**Returns:** `bool`

**Example:**
```python
from authz.services import user_has_role

if user_has_role(user, "Admin"):
    # Show admin panel
    pass
```

##### `bulk_assign_roles(users, role_names, created_by=None)`

Assign multiple roles to multiple users.

**Parameters:**
- `users` (List[User]) - List of users
- `role_names` (List[str]) - List of role names
- `created_by` (User, optional) - User performing the assignment

**Returns:** `int` - Number of role assignments created

**Raises:** `Role.DoesNotExist` if any role doesn't exist

**Example:**
```python
from authz.services import bulk_assign_roles

users = User.objects.filter(department="Engineering")
count = bulk_assign_roles(users, ["Developer", "Tester"], created_by=admin)
print(f"Created {count} role assignments")
```

#### Permission Management

##### `grant_permission(user, permission_code, created_by=None)`

Grant a permission directly to a user (explicit allow).

**Parameters:**
- `user` - User instance
- `permission_code` (str) - Permission code
- `created_by` (User, optional) - User granting the permission

**Returns:** `UserPermission` instance

**Raises:** `Permission.DoesNotExist` if permission doesn't exist

**Example:**
```python
from authz.services import grant_permission

# Grant special permission to one user
user_perm = grant_permission(user, "reports.export_all", created_by=admin)
```

##### `deny_permission(user, permission_code, created_by=None)`

Explicitly deny a permission for a user (overrides role permissions).

**Parameters:**
- `user` - User instance
- `permission_code` (str) - Permission code
- `created_by` (User, optional) - User creating the denial

**Returns:** `UserPermission` instance

**Raises:** `Permission.DoesNotExist` if permission doesn't exist

**Example:**
```python
from authz.services import deny_permission

# Deny a specific permission even if user has it via role
user_perm = deny_permission(user, "users.delete", created_by=admin)
```

##### `revoke_user_permission(user, permission_code)`

Remove an explicit permission override (allow or deny).

**Parameters:**
- `user` - User instance
- `permission_code` (str) - Permission code

**Returns:** `bool` - True if override was removed, False if no override existed

**Example:**
```python
from authz.services import revoke_user_permission

success = revoke_user_permission(user, "reports.export_all")
```

##### `get_user_permissions(user, include_roles=True)`

Get all permissions for a user with their sources.

**Parameters:**
- `user` - User instance
- `include_roles` (bool) - Whether to include role-based permissions

**Returns:** `List[dict]` - List of permission dictionaries

**Example:**
```python
from authz.services import get_user_permissions

permissions = get_user_permissions(user)
for perm in permissions:
    print(f"{perm['code']} from {perm['source']}")
    # Output: "articles.create from role (Author)"
    #         "reports.export from explicit"
```

##### `get_permission_matrix(user)`

Get a comprehensive permission matrix for a user.

**Parameters:**
- `user` - User instance

**Returns:** `dict` - Permission matrix with roles and permissions

**Example:**
```python
from authz.services import get_permission_matrix

matrix = get_permission_matrix(user)
print(matrix)
# {
#     'explicit_allows': ['reports.export'],
#     'explicit_denies': [],
#     'roles': {
#         'Author': ['articles.create', 'articles.edit'],
#         'Reviewer': ['articles.review']
#     },
#     'all_permissions': ['articles.create', 'articles.edit', 'articles.review', 'reports.export']
# }
```

#### Utility Functions

##### `get_users_with_permission(permission_code)`

Find all users who have a specific permission (via roles or explicit grants).

**Parameters:**
- `permission_code` (str) - Permission code

**Returns:** `List[User]` - List of users

**Example:**
```python
from authz.services import get_users_with_permission

users = get_users_with_permission("articles.publish")
for user in users:
    notify_user(user, "New article pending review")
```

##### `get_users_with_role(role_name)`

Find all users who have a specific role.

**Parameters:**
- `role_name` (str) - Role name

**Returns:** `List[User]` - List of users

**Example:**
```python
from authz.services import get_users_with_role

admins = get_users_with_role("Admin")
```

---

### Decorators

#### `@require_permission(permission_code)`

Decorator for function-based views that requires a permission.

**Parameters:**
- `permission_code` (str) - Required permission code

**Behavior:**
- If user has permission: View executes normally
- If user lacks permission: Returns HTTP 403 Forbidden

**Example:**
```python
from authz.decorators import require_permission
from django.http import JsonResponse

@require_permission("articles.create")
def create_article(request):
    # Only users with "articles.create" permission can access this
    article = Article.objects.create(
        title=request.POST['title'],
        author=request.user
    )
    return JsonResponse({"id": article.id})
```

**With object-level permissions:**
```python
from authz.decorators import require_permission

@require_permission("articles.edit")
def edit_article(request, article_id):
    article = Article.objects.get(pk=article_id)
    
    # Additional object-level check
    from authz.engine import authorize
    if not authorize(request.user, "articles.edit", obj=article):
        return HttpResponseForbidden("You can only edit your own articles")
    
    article.title = request.POST['title']
    article.save()
    return JsonResponse({"success": True})
```

---

### Mixins

#### `PermissionRequiredMixin`

Mixin for class-based views that requires a permission.

**Attributes:**
- `permission_required` (str) - Required permission code
- `permission_denied_message` (str, optional) - Custom error message

**Behavior:**
- Checks permission before dispatching the view
- Returns HTTP 403 if permission is denied

**Example:**
```python
from authz.mixins import PermissionRequiredMixin
from django.views.generic import CreateView

class ArticleCreateView(PermissionRequiredMixin, CreateView):
    model = Article
    permission_required = "articles.create"
    permission_denied_message = "You need Author role to create articles"
    template_name = "articles/create.html"
    fields = ['title', 'content']
```

**With multiple permissions:**
```python
class ArticlePublishView(PermissionRequiredMixin, UpdateView):
    model = Article
    permission_required = "articles.publish"  # Only one permission supported
    # For multiple permissions, override has_permission method
```

---

### Django REST Framework Integration

#### `AuthzPermission`

DRF permission class for API views.

**Usage:**
```python
from rest_framework import viewsets
from authz.drf_permissions import AuthzPermission

class ArticleViewSet(viewsets.ModelViewSet):
    queryset = Article.objects.all()
    serializer_class = ArticleSerializer
    permission_classes = [AuthzPermission]
    
    # Define permission for each action
    permission_code = "articles.view"  # Default for all actions
    
    def get_permission_code(self):
        """Override to use different permissions per action"""
        if self.action == 'create':
            return "articles.create"
        elif self.action in ['update', 'partial_update']:
            return "articles.edit"
        elif self.action == 'destroy':
            return "articles.delete"
        return "articles.view"
```

**Object-level permissions:**
```python
class ArticleViewSet(viewsets.ModelViewSet):
    permission_classes = [AuthzPermission]
    
    def get_permission_code(self):
        if self.action in ['update', 'partial_update']:
            return "articles.edit"
        return "articles.view"
    
    def check_object_permissions(self, request, obj):
        """DRF calls this for object-level checks"""
        super().check_object_permissions(request, obj)
        
        # Additional authz check with object
        from authz.engine import authorize
        if not authorize(request.user, self.get_permission_code(), obj=obj):
            self.permission_denied(request, message="You can only edit your own articles")
```

---

### Template Tags

#### `{% load authz_tags %}`

Load the authz template tags.

#### `{% if_has_permission 'permission_code' object %}`

Conditionally render content based on permission.

**Parameters:**
- `permission_code` (str) - Permission to check
- `object` (optional) - Object for object-level permission check

**Example:**
```django
{% load authz_tags %}

<div class="article">
    <h1>{{ article.title }}</h1>
    <p>{{ article.content }}</p>
    
    {% if_has_permission 'articles.edit' article %}
        <a href="{% url 'edit_article' article.pk %}" class="btn">Edit</a>
    {% endif_has_permission %}
    
    {% if_has_permission 'articles.delete' article %}
        <a href="{% url 'delete_article' article.pk %}" class="btn btn-danger">Delete</a>
    {% endif_has_permission %}
</div>
```

**Without object:**
```django
{% if_has_permission 'articles.create' %}
    <a href="{% url 'create_article' %}" class="btn btn-primary">Create New Article</a>
{% endif_has_permission %}
```

---

## GraphQL API

The library provides a complete GraphQL API for managing permissions and roles.

### Setup

Include the authz schema in your main GraphQL schema:

```python
import graphene
from authz.queries import AuthzQuery
from authz.mutations import AuthzMutation

class Query(AuthzQuery, graphene.ObjectType):
    pass

class Mutation(AuthzMutation, graphene.ObjectType):
    pass

schema = graphene.Schema(query=Query, mutation=Mutation)
```

### Queries

#### `permissions(search, page, page_size)`

List all permissions with optional search and pagination.

**Arguments:**
- `search` (String, optional) - Search in code and description
- `page` (Int, optional) - Page number (default: 1)
- `page_size` (Int, optional) - Items per page (default: 20)

**Returns:** `PermissionListDTO`

**Example:**
```graphql
query {
  permissions(search: "articles", page: 1, pageSize: 10) {
    response {
      status
      message
    }
    data {
      id
      code
      description
      isActive
    }
  }
}
```

#### `roles(search, page, page_size)`

List all roles with optional search and pagination.

**Arguments:**
- `search` (String, optional) - Search in name and description
- `page` (Int, optional) - Page number
- `page_size` (Int, optional) - Items per page

**Returns:** `RoleListDTO`

**Example:**
```graphql
query {
  roles(search: "author", page: 1, pageSize: 10) {
    response {
      status
      message
    }
    data {
      id
      name
      description
      permissions {
        code
        description
      }
    }
  }
}
```

#### `role(id)`

Get a single role by ID.

**Arguments:**
- `id` (UUID, required) - Role ID

**Returns:** `RoleSingleDTO`

**Example:**
```graphql
query {
  role(id: "123e4567-e89b-12d3-a456-426614174000") {
    response {
      status
      message
    }
    data {
      role {
        id
        name
        description
        permissions {
          code
          description
        }
      }
    }
  }
}
```

#### `userAuthorizationDetails(userId)`

Get complete authorization details for a user.

**Arguments:**
- `userId` (ID, required) - User ID

**Returns:** `UserAuthorizationDetailsDTO`

**Example:**
```graphql
query {
  userAuthorizationDetails(userId: "123") {
    response {
      status
      message
    }
    data {
      roles {
        name
        permissions {
          code
        }
      }
      explicitPermissions {
        permission {
          code
        }
        allow
      }
      allPermissionCodes
    }
  }
}
```

### Mutations

#### `createPermission(input)`

Create a new permission.

**Input:**
- `code` (String, required) - Permission code
- `description` (String, optional) - Description

**Example:**
```graphql
mutation {
  createPermission(input: {
    code: "articles.publish"
    description: "Allows publishing articles"
  }) {
    response {
      status
      message
    }
    data {
      id
      code
      description
    }
  }
}
```

#### `updatePermission(input)`

Update an existing permission.

**Input:**
- `id` (UUID, required) - Permission ID
- `description` (String, optional) - New description
- `isActive` (Boolean, optional) - Active status

**Example:**
```graphql
mutation {
  updatePermission(input: {
    id: "123e4567-e89b-12d3-a456-426614174000"
    description: "Updated description"
    isActive: true
  }) {
    response {
      status
      message
    }
    data {
      id
      code
      description
    }
  }
}
```

#### `deletePermission(id)`

Delete a permission.

**Arguments:**
- `id` (ID, required) - Permission ID

**Example:**
```graphql
mutation {
  deletePermission(id: "123e4567-e89b-12d3-a456-426614174000") {
    response {
      status
      message
    }
  }
}
```

#### `createRole(input)`

Create a new role.

**Input:**
- `name` (String, required) - Role name
- `description` (String, optional) - Description
- `permissionCodes` (List[String], optional) - Permission codes to add

**Example:**
```graphql
mutation {
  createRole(input: {
    name: "Content Manager"
    description: "Manages all content"
    permissionCodes: ["articles.create", "articles.edit", "articles.publish"]
  }) {
    response {
      status
      message
    }
    data {
      id
      name
      permissions {
        code
      }
    }
  }
}
```

#### `updateRole(input)`

Update an existing role.

**Input:**
- `id` (UUID, required) - Role ID
- `name` (String, optional) - New name
- `description` (String, optional) - New description
- `permissionCodes` (List[String], optional) - New permission codes (replaces existing)
- `isActive` (Boolean, optional) - Active status

**Example:**
```graphql
mutation {
  updateRole(input: {
    id: "123e4567-e89b-12d3-a456-426614174000"
    name: "Senior Editor"
    permissionCodes: ["articles.create", "articles.edit", "articles.publish", "articles.delete"]
  }) {
    response {
      status
      message
    }
  }
}
```

#### `deleteRole(id)`

Delete a role.

**Arguments:**
- `id` (ID, required) - Role ID

**Example:**
```graphql
mutation {
  deleteRole(id: "123e4567-e89b-12d3-a456-426614174000") {
    response {
      status
      message
    }
  }
}
```

#### `assignRole(input)`

Assign a role to a user.

**Input:**
- `userId` (ID, required) - User ID
- `roleName` (String, required) - Role name

**Example:**
```graphql
mutation {
  assignRole(input: {
    userId: "456"
    roleName: "Author"
  }) {
    response {
      status
      message
    }
  }
}
```

#### `revokeRole(input)`

Revoke a role from a user.

**Input:**
- `userId` (ID, required) - User ID
- `roleName` (String, required) - Role name

**Example:**
```graphql
mutation {
  revokeRole(input: {
    userId: "456"
    roleName: "Author"
  }) {
    response {
      status
      message
    }
  }
}
```

#### `grantPermission(input)`

Grant an explicit permission to a user.

**Input:**
- `userId` (ID, required) - User ID
- `permissionCode` (String, required) - Permission code

**Example:**
```graphql
mutation {
  grantPermission(input: {
    userId: "456"
    permissionCode: "reports.export_all"
  }) {
    response {
      status
      message
    }
  }
}
```

#### `denyPermission(input)`

Explicitly deny a permission for a user.

**Input:**
- `userId` (ID, required) - User ID
- `permissionCode` (String, required) - Permission code

**Example:**
```graphql
mutation {
  denyPermission(input: {
    userId: "456"
    permissionCode: "users.delete"
  }) {
    response {
      status
      message
    }
  }
}
```

#### `revokeUserPermission(input)`

Remove an explicit permission override.

**Input:**
- `userId` (ID, required) - User ID
- `permissionCode` (String, required) - Permission code

**Example:**
```graphql
mutation {
  revokeUserPermission(input: {
    userId: "456"
    permissionCode: "reports.export_all"
  }) {
    response {
      status
      message
    }
  }
}
```

---

## Usage Examples

### Example 1: Basic Permission Checking

```python
from authz.engine import authorize
from django.http import HttpResponseForbidden

def delete_article(request, article_id):
    article = Article.objects.get(pk=article_id)
    
    # Check permission
    if not authorize(request.user, "articles.delete"):
        return HttpResponseForbidden("You don't have permission to delete articles")
    
    article.delete()
    return JsonResponse({"success": True})
```

### Example 2: Role-Based Dashboard Access

```python
from authz.services import user_has_role
from django.shortcuts import render, redirect

def dashboard(request):
    user = request.user
    
    if user_has_role(user, "Admin"):
        return render(request, "admin_dashboard.html")
    elif user_has_role(user, "Manager"):
        return render(request, "manager_dashboard.html")
    elif user_has_role(user, "Employee"):
        return render(request, "employee_dashboard.html")
    else:
        return redirect("access_denied")
```

### Example 3: Resource Ownership Policy

```python
from authz.policies import BasePolicy, register_policy

@register_policy
class ArticleOwnerPolicy(BasePolicy):
    permission_code = "articles.edit"
    
    def allows(self, user, obj=None, context=None):
        """Only allow editing own articles"""
        if not obj:
            return True  # Allow if no specific object (e.g., list view)
        
        if hasattr(obj, 'author'):
            return obj.author == user
        
        return False
    
    def get_denial_reason(self, user, obj=None, context=None):
        return "You can only edit articles you authored"

# Now use it in a view
from authz.engine import authorize

def edit_article(request, article_id):
    article = Article.objects.get(pk=article_id)
    
    # This will check both RBAC and the ownership policy
    if not authorize(request.user, "articles.edit", obj=article):
        return HttpResponseForbidden("You can only edit your own articles")
    
    # Process edit
    article.title = request.POST['title']
    article.save()
    return JsonResponse({"success": True})
```

### Example 4: Feature Flags

```python
# Create feature permissions
from authz.models import Permission, Role

# Create premium features
Permission.objects.create(
    code="features.advanced_analytics",
    description="Access to advanced analytics dashboard"
)

Permission.objects.create(
    code="features.export_data",
    description="Export data to CSV/Excel"
)

# Create premium role
premium_role = Role.objects.create(
    name="Premium User",
    description="Users with premium subscription"
)
premium_role.add_permission("features.advanced_analytics")
premium_role.add_permission("features.export_data")

# In your view
from authz.engine import authorize

def analytics_dashboard(request):
    if not authorize(request.user, "features.advanced_analytics"):
        return render(request, "upgrade_to_premium.html")
    
    # Show advanced analytics
    return render(request, "analytics.html")
```

### Example 5: Multi-Tenant Permissions

```python
from authz.policies import BasePolicy, register_policy

@register_policy
class TenantAccessPolicy(BasePolicy):
    permission_code = "documents.view"
    
    def allows(self, user, obj=None, context=None):
        """Only allow access to documents in user's tenant"""
        if not obj:
            return True
        
        if hasattr(obj, 'tenant_id') and hasattr(user, 'tenant_id'):
            return obj.tenant_id == user.tenant_id
        
        return False
    
    def get_denial_reason(self, user, obj=None, context=None):
        return "You can only access documents in your organization"
```

### Example 6: Time-Based Access

```python
from authz.policies import BasePolicy, register_policy
from django.utils import timezone

@register_policy
class BusinessHoursPolicy(BasePolicy):
    permission_code = "reports.generate"
    
    def allows(self, user, obj=None, context=None):
        """Only allow report generation during business hours"""
        now = timezone.now()
        hour = now.hour
        
        # Business hours: 8 AM to 6 PM
        if 8 <= hour < 18:
            return True
        
        # Admins can generate reports anytime
        return user.is_superuser
    
    def get_denial_reason(self, user, obj=None, context=None):
        return "Reports can only be generated during business hours (8 AM - 6 PM)"
```

### Example 7: Conditional Rendering in Templates

```django
{% load authz_tags %}

<div class="article-list">
    {% for article in articles %}
        <div class="article">
            <h2>{{ article.title }}</h2>
            <p>{{ article.excerpt }}</p>
            
            <div class="actions">
                <a href="{% url 'view_article' article.pk %}">View</a>
                
                {% if_has_permission 'articles.edit' article %}
                    <a href="{% url 'edit_article' article.pk %}">Edit</a>
                {% endif_has_permission %}
                
                {% if_has_permission 'articles.delete' article %}
                    <a href="{% url 'delete_article' article.pk %}" class="danger">Delete</a>
                {% endif_has_permission %}
            </div>
        </div>
    {% endfor %}
    
    {% if_has_permission 'articles.create' %}
        <a href="{% url 'create_article' %}" class="btn btn-primary">Create New Article</a>
    {% endif_has_permission %}
</div>
```

### Example 8: DRF API with Per-Action Permissions

```python
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from authz.drf_permissions import AuthzPermission
from authz.engine import authorize

class ArticleViewSet(viewsets.ModelViewSet):
    queryset = Article.objects.all()
    serializer_class = ArticleSerializer
    permission_classes = [AuthzPermission]
    
    def get_permission_code(self):
        """Different permissions for different actions"""
        action_permissions = {
            'list': 'articles.view',
            'retrieve': 'articles.view',
            'create': 'articles.create',
            'update': 'articles.edit',
            'partial_update': 'articles.edit',
            'destroy': 'articles.delete',
            'publish': 'articles.publish',
        }
        return action_permissions.get(self.action, 'articles.view')
    
    @action(detail=True, methods=['post'])
    def publish(self, request, pk=None):
        """Custom action to publish an article"""
        article = self.get_object()
        
        # Permission already checked by AuthzPermission
        article.status = 'published'
        article.published_at = timezone.now()
        article.save()
        
        return Response({'status': 'published'})
    
    def perform_update(self, serializer):
        """Additional object-level check"""
        article = self.get_object()
        
        # Check if user can edit this specific article
        if not authorize(self.request.user, "articles.edit", obj=article):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied("You can only edit your own articles")
        
        serializer.save()
```

---

## Django Admin

The library provides full Django admin integration for managing permissions and roles.

### Accessing the Admin

Navigate to `/admin/authz/` to access the authorization admin.

### Available Admin Interfaces

#### Permission Admin (`/admin/authz/permission/`)

**Features:**
- List all permissions with search and filtering
- Search by code or description
- Filter by active status
- Create, edit, and delete permissions
- Bulk actions

**Fields:**
- Code (editable)
- Description (editable)
- Is Active (editable)
- Created At (read-only)
- Updated At (read-only)

#### Role Admin (`/admin/authz/role/`)

**Features:**
- List all roles with search and filtering
- Search by name or description
- Filter by active status
- Manage role permissions via inline interface
- Create, edit, and delete roles

**Fields:**
- Name (editable)
- Description (editable)
- Permissions (many-to-many widget)
- Is Active (editable)
- Created At (read-only)
- Updated At (read-only)

#### UserRole Admin (`/admin/authz/userrole/`)

**Features:**
- View all user-role assignments
- Search by user or role
- Filter by role or creation date
- See who assigned each role and when

**Fields:**
- User (editable)
- Role (editable)
- Created At (read-only)
- Created By (read-only)

#### UserPermission Admin (`/admin/authz/userpermission/`)

**Features:**
- View all explicit permission overrides
- Search by user or permission
- Filter by allow/deny status
- See who created each override

**Fields:**
- User (editable)
- Permission (editable)
- Allow (editable - True = grant, False = deny)
- Created At (read-only)
- Created By (read-only)

### Admin Best Practices

1. **Use Search**: With many permissions/roles, use the search box to find what you need
2. **Bulk Actions**: Select multiple items and use bulk actions for efficiency
3. **Audit Trail**: Always check "Created By" and "Created At" for audit purposes
4. **Read-Only Fields**: Timestamps and audit fields are read-only for data integrity

---

## Best Practices

### 1. Permission Naming Conventions

Use the `namespace.action` format for all permissions:

**Good:**
- `articles.create`
- `articles.edit`
- `articles.delete`
- `articles.publish`
- `users.view`
- `users.edit`
- `reports.export`

**Bad:**
- `create_article` (no namespace)
- `articles` (no action)
- `ArticleCreate` (wrong case)

**Benefits:**
- Easy to understand and search
- Groups related permissions
- Consistent across the application

### 2. Role Design Patterns

Create roles based on job functions or user types:

**Examples:**
```python
# Content roles
author_role = Role.objects.create(name="Author")
author_role.add_permission("articles.create")
author_role.add_permission("articles.edit")  # Own articles only via policy

editor_role = Role.objects.create(name="Editor")
editor_role.add_permission("articles.create")
editor_role.add_permission("articles.edit")
editor_role.add_permission("articles.publish")

# User management roles
user_manager_role = Role.objects.create(name="User Manager")
user_manager_role.add_permission("users.view")
user_manager_role.add_permission("users.edit")
user_manager_role.add_permission("users.create")

# Admin role
admin_role = Role.objects.create(name="Admin")
# Add all permissions
```

### 3. Use Policies for Complex Rules

Don't try to model everything with RBAC. Use policies for:
- Resource ownership
- Time-based access
- Quota limits
- Business rules
- Conditional logic

**Example:**
```python
@register_policy
class ArticleEditPolicy(BasePolicy):
    permission_code = "articles.edit"
    
    def allows(self, user, obj=None, context=None):
        # Authors can only edit their own articles
        # Editors can edit any article
        if user_has_role(user, "Editor"):
            return True
        
        if obj and hasattr(obj, 'author'):
            return obj.author == user
        
        return False
```

### 4. Explicit Denies - Use Sparingly

Explicit denies override all role permissions. Only use them when:
- Temporarily suspending a user's specific permission
- Overriding a role permission for a specific user
- Implementing exceptions to general rules

**Example:**
```python
# User is an Editor but we want to prevent them from deleting
from authz.services import deny_permission

deny_permission(user, "articles.delete", created_by=admin)
```

### 5. Always Pass `created_by`

For audit trails, always pass `created_by` when assigning roles or permissions:

```python
from authz.services import assign_role, grant_permission

# Good
assign_role(user, "Author", created_by=request.user)
grant_permission(user, "reports.export", created_by=request.user)

# Bad (no audit trail)
assign_role(user, "Author")
```

### 6. Check Permissions on Both Frontend and Backend

**Frontend (UI):**
```django
{% if_has_permission 'articles.delete' article %}
    <button>Delete</button>
{% endif_has_permission %}
```

**Backend (Security):**
```python
@require_permission("articles.delete")
def delete_article(request, article_id):
    # Actual deletion logic
    pass
```

Never rely on frontend checks alone - always enforce on the backend.

### 7. Performance Optimization

**Use `select_related` and `prefetch_related`:**
```python
# When querying users with roles
users = User.objects.prefetch_related('user_roles__role__permissions').all()

# When checking multiple permissions
from authz.engine import get_user_permission_codes
codes = get_user_permission_codes(user)  # Cached result
```

**Cache permission checks for the request:**
```python
# In middleware or view
def my_view(request):
    # Cache user permissions for this request
    request.user._permission_cache = get_user_permission_codes(request.user)
    
    # Now multiple authorize() calls will be faster
```

### 8. Testing Authorization

Always test both positive and negative cases:

```python
from django.test import TestCase
from authz.engine import authorize
from authz.services import assign_role

class AuthorizationTestCase(TestCase):
    def test_author_can_create_articles(self):
        """Test that authors can create articles"""
        assign_role(self.user, "Author")
        self.assertTrue(authorize(self.user, "articles.create"))
    
    def test_guest_cannot_create_articles(self):
        """Test that guests cannot create articles"""
        self.assertFalse(authorize(self.user, "articles.create"))
    
    def test_author_can_only_edit_own_articles(self):
        """Test ownership policy"""
        assign_role(self.user, "Author")
        
        # Own article
        own_article = Article.objects.create(author=self.user)
        self.assertTrue(authorize(self.user, "articles.edit", obj=own_article))
        
        # Someone else's article
        other_article = Article.objects.create(author=self.other_user)
        self.assertFalse(authorize(self.user, "articles.edit", obj=other_article))
```

---

## Testing

### Running the Test Suite

The library includes comprehensive tests. Run them with:

```bash
python manage.py test authz
```

Expected output:
```
Creating test database...
...........................
----------------------------------------------------------------------
Ran 28 tests in 2.345s

OK
```

### Writing Tests for Your Authorization Logic

**Example test file:**
```python
from django.test import TestCase
from django.contrib.auth import get_user_model
from authz.models import Permission, Role
from authz.services import assign_role, grant_permission, deny_permission
from authz.engine import authorize

User = get_user_model()

class ArticleAuthorizationTest(TestCase):
    def setUp(self):
        """Set up test data"""
        # Create users
        self.author = User.objects.create_user(username="author")
        self.editor = User.objects.create_user(username="editor")
        self.guest = User.objects.create_user(username="guest")
        
        # Create permissions
        Permission.objects.create(code="articles.create")
        Permission.objects.create(code="articles.edit")
        Permission.objects.create(code="articles.delete")
        Permission.objects.create(code="articles.publish")
        
        # Create roles
        author_role = Role.objects.create(name="Author")
        author_role.add_permission("articles.create")
        author_role.add_permission("articles.edit")
        
        editor_role = Role.objects.create(name="Editor")
        editor_role.add_permission("articles.create")
        editor_role.add_permission("articles.edit")
        editor_role.add_permission("articles.publish")
        
        # Assign roles
        assign_role(self.author, "Author")
        assign_role(self.editor, "Editor")
    
    def test_author_can_create(self):
        """Authors can create articles"""
        self.assertTrue(authorize(self.author, "articles.create"))
    
    def test_author_cannot_publish(self):
        """Authors cannot publish articles"""
        self.assertFalse(authorize(self.author, "articles.publish"))
    
    def test_editor_can_publish(self):
        """Editors can publish articles"""
        self.assertTrue(authorize(self.editor, "articles.publish"))
    
    def test_guest_has_no_permissions(self):
        """Guests have no permissions"""
        self.assertFalse(authorize(self.guest, "articles.create"))
        self.assertFalse(authorize(self.guest, "articles.edit"))
        self.assertFalse(authorize(self.guest, "articles.publish"))
    
    def test_explicit_deny_overrides_role(self):
        """Explicit deny overrides role permissions"""
        # Editor normally can publish
        self.assertTrue(authorize(self.editor, "articles.publish"))
        
        # Deny the permission
        deny_permission(self.editor, "articles.publish")
        
        # Now they can't
        self.assertFalse(authorize(self.editor, "articles.publish"))
    
    def test_explicit_grant(self):
        """Explicit grant gives permission"""
        # Guest normally can't create
        self.assertFalse(authorize(self.guest, "articles.create"))
        
        # Grant the permission
        grant_permission(self.guest, "articles.create")
        
        # Now they can
        self.assertTrue(authorize(self.guest, "articles.create"))
```

---

## Troubleshooting

### Common Issues and Solutions

#### Issue: "Permission denied" even though user has the role

**Possible causes:**
1. Role is inactive (`is_active=False`)
2. Permission is inactive
3. User has an explicit deny
4. A policy is denying access

**Solution:**
```python
from authz.services import get_permission_matrix

# Check user's complete permission matrix
matrix = get_permission_matrix(user)
print(matrix)

# Check for explicit denies
if permission_code in matrix['explicit_denies']:
    print("User has explicit deny for this permission")

# Check if role is active
from authz.models import Role
role = Role.objects.get(name="Author")
print(f"Role active: {role.is_active}")

# Check if permission is active
from authz.models import Permission
perm = Permission.objects.get(code="articles.create")
print(f"Permission active: {perm.is_active}")
```

#### Issue: Migrations fail with "relation already exists"

**Cause:** Database tables already exist from a previous installation

**Solution:**
```bash
# Option 1: Fake the initial migration
python manage.py migrate authz --fake-initial

# Option 2: Drop tables and re-migrate (CAUTION: loses data)
python manage.py migrate authz zero
python manage.py migrate authz
```

#### Issue: "Role.DoesNotExist" when assigning role

**Cause:** Role hasn't been created yet

**Solution:**
```python
from authz.models import Role

# Check if role exists
if not Role.objects.filter(name="Author").exists():
    # Create it
    role = Role.objects.create(
        name="Author",
        description="Can create and edit articles"
    )
    role.add_permission("articles.create")
    role.add_permission("articles.edit")

# Now assign
from authz.services import assign_role
assign_role(user, "Author")
```

#### Issue: GraphQL mutations return "Permission denied"

**Cause:** GraphQL mutations require superuser access by default

**Solution:**
```python
# Make sure the user making the request is a superuser
user.is_superuser = True
user.save()

# Or modify the mutation to check for a specific permission instead
# (requires editing the library code)
```

#### Issue: Template tag not working

**Cause:** Forgot to load the template tags

**Solution:**
```django
{# Add this at the top of your template #}
{% load authz_tags %}

{# Now you can use the tags #}
{% if_has_permission 'articles.create' %}
    ...
{% endif_has_permission %}
```

#### Issue: Performance problems with many users/roles

**Cause:** N+1 query problem or missing indexes

**Solution:**
```python
# Use select_related and prefetch_related
users = User.objects.prefetch_related(
    'user_roles__role__permissions'
).all()

# Cache permission checks
from authz.engine import get_user_permission_codes
user_perms = get_user_permission_codes(user)  # Cache this

# Check if permission is in cache
if "articles.create" in user_perms:
    # Allow
    pass
```

#### Issue: Policies not being evaluated

**Cause:** Policy not registered or permission code doesn't match

**Solution:**
```python
from authz.policies import BasePolicy, register_policy

# Make sure you use the @register_policy decorator
@register_policy
class MyPolicy(BasePolicy):
    # Make sure this matches exactly
    permission_code = "articles.edit"  # Must match what you're checking
    
    def allows(self, user, obj=None, context=None):
        return True

# Verify policy is registered
from authz.policies import policy_registry
print(policy_registry.get_policies("articles.edit"))
```

### Debugging Tips

**Enable logging:**
```python
# In settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'authz': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}
```

**Check authorization flow:**
```python
from authz.engine import authorize

# Add print statements or use debugger
import pdb; pdb.set_trace()

result = authorize(user, "articles.create")
print(f"Authorization result: {result}")
```

**Inspect user permissions:**
```python
from authz.services import get_user_permissions, get_permission_matrix

# Get all permissions with sources
perms = get_user_permissions(user)
for perm in perms:
    print(f"{perm['code']} from {perm['source']}")

# Get complete matrix
matrix = get_permission_matrix(user)
print("Explicit allows:", matrix['explicit_allows'])
print("Explicit denies:", matrix['explicit_denies'])
print("Roles:", matrix['roles'])
print("All permissions:", matrix['all_permissions'])
```

---

## License

MIT License. See [LICENSE](LICENSE) file for details.

---

## Support and Contributing

### Getting Help

- **Documentation**: You're reading it!
- **Issues**: Report bugs or request features on GitHub
- **Questions**: Open a discussion on GitHub

### Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Write tests for your changes
4. Submit a pull request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/tarxemo/tarxemo-django-authz.git
cd tarxemo-django-authz

# Install in development mode
pip install -e .

# Install development dependencies
pip install -e .[drf]

# Run tests
python manage.py test authz
```

---

**Made with ❤️ by TarXemo**

# Django Authorization Framework (`tarxemo-django-authz`)

A comprehensive, reusable Django authorization framework supporting both Role-Based Access Control (RBAC) and Policy-Based Access Control (PBAC).

## Features

- ✅ **RBAC**: Roles, permissions, user assignments with audit trails
- ✅ **PBAC**: Custom policy system for dynamic business rules
- ✅ **Deny-First Security**: Explicit denies override all allows
- ✅ **Enforcement Tools**: Decorators, mixins, template tags, DRF integration
- ✅ **Django Admin**: Full admin interfaces for managing permissions and roles
- ✅ **Separation of Concerns**: Authorization logic separate from business models
- ✅ **Production-Ready**: Comprehensive validation, error handling, optimized queries
- ✅ **Graphene Support**: GraphQL mutations and queries for authorization management

## Installation

```bash
pip install tarxemo-django-authz
```

Or for development:

```bash
pip install git+https://github.com/tarxemo/tarxemo-django-authz.git
```

## Setup

### 1. Register in `INSTALLED_APPS`

Add `authz` to your Django settings:

```python
INSTALLED_APPS = [
    # ...
    'authz',
    'tarxemo_django_graphene_utils', # Dependency
]
```

### 2. Configure Authentication (Optional but Recommended)

Ensure your User model is compatible with Django's standard authentication.

### 3. Run Migrations

```bash
python manage.py migrate
```

## Quick Start

### 1. Create Permissions

```python
from authz.models import Permission

Permission.objects.create(
    code="articles.create",
    description="Create articles"
)
```

### 2. Create Roles

```python
from authz.models import Role

author_role = Role.objects.create(name="Author")
author_role.add_permission("articles.create")
```

### 3. Assign Roles

```python
from authz.services import assign_role

assign_role(user, "Author")
```

### 4. Check Permissions

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

### GraphQL Integration

Include the schema in your main Graphene schema:

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

## License

MIT License. See [LICENSE](LICENSE) for details.
# tarxemo-django-authz

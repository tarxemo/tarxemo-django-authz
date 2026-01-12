# Authz Usage Examples

This document provides practical examples of using the authz authorization framework in your Bhumwi project.

## Backend Usage

### 1. Creating Permissions and Roles

```python
from authz.models import Permission, Role
from authz.services import assign_role

# Create permissions
perm_create = Permission.objects.create(
    code="properties.create",
    description="Create new properties"
)

perm_edit = Permission.objects.create(
    code="properties.edit",
    description="Edit existing properties"
)

perm_delete = Permission.objects.create(
    code="properties.delete",
    description="Delete properties"
)

# Create a role
manager_role = Role.objects.create(
    name="Property Manager",
    description="Can manage all property operations"
)

# Add permissions to role
manager_role.add_permission("properties.create")
manager_role.add_permission("properties.edit")
manager_role.add_permission("properties.delete")

# Assign role to user
from bhumwi_auth.models import CustomUser
user = CustomUser.objects.get(email="manager@example.com")
assign_role(user, "Property Manager", created_by=request.user)
```

### 2. Checking Permissions in Views

```python
from authz.decorators import require_permission
from authz.engine import authorize

# Using decorator
@require_permission("properties.create")
def create_property(request):
    # User has permission, proceed
    return JsonResponse({"status": "success"})

# Using function
def edit_property(request, property_id):
    if not authorize(request.user, "properties.edit"):
        return JsonResponse({"error": "Permission denied"}, status=403)
    
    # Proceed with edit
    return JsonResponse({"status": "success"})
```

### 3. Using in Class-Based Views

```python
from authz.mixins import PermissionRequiredMixin
from django.views.generic import CreateView

class PropertyCreateView(PermissionRequiredMixin, CreateView):
    model = Property
    permission_required = "properties.create"
    template_name = "properties/create.html"
```

### 4. Custom Policies

```python
from authz.policies import BasePolicy, register_policy

@register_policy
class OwnerOnlyPolicy(BasePolicy):
    permission_code = "properties.edit"
    
    def allows(self, user, obj=None, context=None):
        # Only allow if user owns the property
        if obj and hasattr(obj, 'owner'):
            return obj.owner == user
        return False
    
    def get_denial_reason(self, user, obj=None, context=None):
        return "Only the property owner can edit this property"
```

### 5. GraphQL Mutations

```python
# In your GraphQL mutations
from authz.engine import authorize

class CreatePropertyMutation(graphene.Mutation):
    # ... mutation definition ...
    
    def mutate(self, info, input):
        user = info.context.user
        
        # Check permission
        if not authorize(user, "properties.create"):
            return PropertyResponse(
                response=build_error("Permission denied")
            )
        
        # Proceed with creation
        property = Property.objects.create(...)
        return PropertyResponse(...)
```

---

## Frontend Usage

### 1. Using Hooks to Fetch Data

```typescript
import { usePermissions, useRoles, useUserAuthorization } from '../hooks/useAuthz';

function PermissionsManager() {
  const { data, loading, error } = usePermissions('', 1, 20);
  
  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error.message}</div>;
  
  const permissions = data?.permissions?.data || [];
  
  return (
    <div>
      {permissions.map(perm => (
        <div key={perm.id}>{perm.code}</div>
      ))}
    </div>
  );
}
```

### 2. Creating Permissions

```typescript
import { useCreatePermission } from '../hooks/useAuthz';

function CreatePermissionForm() {
  const [createPermission, { loading }] = useCreatePermission();
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      const { data } = await createPermission({
        variables: {
          input: {
            code: 'bookings.cancel',
            description: 'Cancel bookings'
          }
        }
      });
      
      if (data?.createPermission?.response?.status) {
        alert('Permission created!');
      }
    } catch (err) {
      console.error(err);
    }
  };
  
  return <form onSubmit={handleSubmit}>...</form>;
}
```

### 3. Managing Roles

```typescript
import { useCreateRole, usePermissions } from '../hooks/useAuthz';

function CreateRoleForm() {
  const [createRole] = useCreateRole();
  const { data: permsData } = usePermissions();
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([]);
  
  const handleSubmit = async () => {
    const { data } = await createRole({
      variables: {
        input: {
          name: 'Guest Manager',
          description: 'Manages guest bookings',
          permissionCodes: selectedPermissions
        }
      }
    });
    
    if (data?.createRole?.response?.status) {
      alert('Role created!');
    }
  };
  
  return (
    <div>
      {/* Role form with permission checkboxes */}
    </div>
  );
}
```

### 4. Assigning Roles to Users

```typescript
import { useAssignRole, useRevokeRole } from '../hooks/useAuthz';

function UserRoleManager({ userId }: { userId: string }) {
  const [assignRole] = useAssignRole();
  const [revokeRole] = useRevokeRole();
  
  const handleAssign = async (roleName: string) => {
    const { data } = await assignRole({
      variables: {
        input: { userId, roleName }
      }
    });
    
    if (data?.assignRole?.response?.status) {
      alert('Role assigned!');
    }
  };
  
  const handleRevoke = async (roleName: string) => {
    const { data } = await revokeRole({
      variables: {
        input: { userId, roleName }
      }
    });
    
    if (data?.revokeRole?.response?.status) {
      alert('Role revoked!');
    }
  };
  
  return (
    <div>
      <button onClick={() => handleAssign('Property Manager')}>
        Assign Manager Role
      </button>
      <button onClick={() => handleRevoke('Property Manager')}>
        Revoke Manager Role
      </button>
    </div>
  );
}
```

### 5. Conditional Rendering with PermissionGuard

```typescript
import { PermissionGuard } from '../components/authz/PermissionGuard';

function PropertyActions({ userId }: { userId: string }) {
  return (
    <div>
      {/* Only show create button if user has permission */}
      <PermissionGuard 
        permission="properties.create" 
        userId={userId}
        fallback={<p>You don't have permission to create properties</p>}
      >
        <button>Create Property</button>
      </PermissionGuard>
      
      {/* Only show delete button if user has permission */}
      <PermissionGuard permission="properties.delete" userId={userId}>
        <button className="danger">Delete Property</button>
      </PermissionGuard>
    </div>
  );
}
```

### 6. Using the Hook Version

```typescript
import { usePermissionCheck } from '../components/authz/PermissionGuard';

function PropertyCard({ userId }: { userId: string }) {
  const canEdit = usePermissionCheck('properties.edit', userId);
  const canDelete = usePermissionCheck('properties.delete', userId);
  
  return (
    <div className="property-card">
      <h3>Property Name</h3>
      <div className="actions">
        {canEdit && <button>Edit</button>}
        {canDelete && <button>Delete</button>}
      </div>
    </div>
  );
}
```

### 7. Using the HOC Version

```typescript
import { withPermission } from '../components/authz/PermissionGuard';

// Component that requires permission
function DeleteButton() {
  return <button className="danger">Delete</button>;
}

// Wrap with permission check
const ProtectedDeleteButton = withPermission(
  'properties.delete',
  <p>You cannot delete properties</p>
)(DeleteButton);

// Use in your app
function PropertyActions() {
  return (
    <div>
      <ProtectedDeleteButton />
    </div>
  );
}
```

---

## Common Patterns

### Pattern 1: Admin-Only Features

```typescript
// Backend
@require_permission("admin.access")
def admin_dashboard(request):
    # Admin-only view
    pass

// Frontend
<PermissionGuard permission="admin.access" userId={currentUser.id}>
  <AdminDashboard />
</PermissionGuard>
```

### Pattern 2: Resource Owner Permissions

```python
# Backend - Custom policy
@register_policy
class ResourceOwnerPolicy(BasePolicy):
    permission_code = "properties.edit"
    
    def allows(self, user, obj=None, context=None):
        return obj and obj.owner_id == user.id

# Frontend - Check in component
const canEdit = usePermissionCheck('properties.edit', userId);
if (canEdit && property.ownerId === userId) {
  // Show edit button
}
```

### Pattern 3: Feature Flags

```python
# Backend - Create feature permissions
Permission.objects.create(
    code="features.advanced_analytics",
    description="Access advanced analytics features"
)

# Assign to premium users
premium_role = Role.objects.get(name="Premium User")
premium_role.add_permission("features.advanced_analytics")
```

```typescript
// Frontend - Show feature based on permission
<PermissionGuard permission="features.advanced_analytics" userId={userId}>
  <AdvancedAnalyticsDashboard />
</PermissionGuard>
```

---

## Testing

### Backend Tests

```python
from django.test import TestCase
from authz.engine import authorize
from authz.models import Permission, Role
from authz.services import assign_role

class AuthzTestCase(TestCase):
    def setUp(self):
        self.user = CustomUser.objects.create(username="testuser")
        self.permission = Permission.objects.create(code="test.permission")
        self.role = Role.objects.create(name="Test Role")
        self.role.add_permission("test.permission")
    
    def test_user_has_permission_via_role(self):
        assign_role(self.user, "Test Role")
        self.assertTrue(authorize(self.user, "test.permission"))
    
    def test_user_without_permission(self):
        self.assertFalse(authorize(self.user, "test.permission"))
```

### Frontend Tests

```typescript
import { render, screen } from '@testing-library/react';
import { MockedProvider } from '@apollo/client/testing';
import { PermissionGuard } from '../components/authz/PermissionGuard';

test('shows content when user has permission', () => {
  const mocks = [
    // Mock GraphQL response
  ];
  
  render(
    <MockedProvider mocks={mocks}>
      <PermissionGuard permission="test.permission" userId="123">
        <div>Protected Content</div>
      </PermissionGuard>
    </MockedProvider>
  );
  
  expect(screen.getByText('Protected Content')).toBeInTheDocument();
});
```

---

## Best Practices

1. **Permission Naming**: Use `namespace.action` format (e.g., `properties.create`, `bookings.cancel`)

2. **Role Design**: Create roles for common user types (e.g., "Property Manager", "Guest", "Admin")

3. **Least Privilege**: Grant minimum permissions needed for each role

4. **Explicit Denies**: Use sparingly, only when you need to override role permissions

5. **Audit Trails**: Always pass `created_by` when assigning roles/permissions programmatically

6. **Frontend Checks**: Use PermissionGuard for UI, but always enforce on backend

7. **Caching**: Consider caching user permissions for better performance

8. **Testing**: Test both positive and negative permission cases

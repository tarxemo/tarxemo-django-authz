import graphene
from tarxemo_django_graphene_utils import BaseResponseDTO

# -----------------------------------------------------------------------------
# Types
# -----------------------------------------------------------------------------

class PermissionType(graphene.ObjectType):
    """Graphene type for Permission model."""
    id = graphene.ID()
    code = graphene.String()
    description = graphene.String()
    is_active = graphene.Boolean()
    created_at = graphene.DateTime()
    updated_at = graphene.DateTime()

class RoleType(graphene.ObjectType):
    """Graphene type for Role model."""
    id = graphene.ID()
    name = graphene.String()
    description = graphene.String()
    is_active = graphene.Boolean()
    created_at = graphene.DateTime()
    updated_at = graphene.DateTime()
    # We expose permissions as a list of codes for simplicity in the list view
    permission_codes = graphene.List(graphene.String)

class UserRoleType(graphene.ObjectType):
    """Graphene type for UserRole model."""
    id = graphene.ID()
    role = graphene.Field(RoleType)
    # We define user generically or use a string representation if user type is not available
    user_id = graphene.ID()
    created_at = graphene.DateTime()

class UserPermissionType(graphene.ObjectType):
    """Graphene type for UserPermission model."""
    id = graphene.ID()
    permission = graphene.Field(PermissionType)
    user_id = graphene.ID()
    allow = graphene.Boolean()
    created_at = graphene.DateTime()

# -----------------------------------------------------------------------------
# Inputs
# -----------------------------------------------------------------------------

class PermissionInput(graphene.InputObjectType):
    code = graphene.String(required=True)
    description = graphene.String()

class PermissionUpdateInput(graphene.InputObjectType):
    id = graphene.ID(required=True)
    description = graphene.String()
    is_active = graphene.Boolean()

class RoleInput(graphene.InputObjectType):
    name = graphene.String(required=True)
    description = graphene.String()
    permission_codes = graphene.List(graphene.String)

class RoleUpdateInput(graphene.InputObjectType):
    id = graphene.ID(required=True)
    name = graphene.String()
    description = graphene.String()
    permission_codes = graphene.List(graphene.String)
    is_active = graphene.Boolean()

class AssignRoleInput(graphene.InputObjectType):
    user_id = graphene.ID(required=True)
    role_name = graphene.String(required=True)

class RevokeRoleInput(graphene.InputObjectType):
    user_id = graphene.ID(required=True)
    role_name = graphene.String(required=True)

class GrantPermissionInput(graphene.InputObjectType):
    user_id = graphene.ID(required=True)
    permission_code = graphene.String(required=True)

class DenyPermissionInput(graphene.InputObjectType):
    user_id = graphene.ID(required=True)
    permission_code = graphene.String(required=True)

class RevokeUserPermissionInput(graphene.InputObjectType):
    user_id = graphene.ID(required=True)
    permission_code = graphene.String(required=True)

# -----------------------------------------------------------------------------
# Response Data Types
# -----------------------------------------------------------------------------

class PermissionSingleDataType(graphene.ObjectType):
    permission = graphene.Field(PermissionType)

class RoleSingleDataType(graphene.ObjectType):
    role = graphene.Field(RoleType)

class UserRoleDataType(graphene.ObjectType):
    user_role = graphene.Field(UserRoleType)

class UserPermissionDataType(graphene.ObjectType):
    user_permission = graphene.Field(UserPermissionType)

# -----------------------------------------------------------------------------
# Response DTOs
# -----------------------------------------------------------------------------

class StandardResponseType(BaseResponseDTO):
    """Standard response with just success/error message."""
    data = graphene.String(required=False)

class PermissionSingleDTO(BaseResponseDTO):
    data = graphene.Field(PermissionSingleDataType)

class PermissionListDTO(BaseResponseDTO):
    data = graphene.List(PermissionType)

class RoleSingleDTO(BaseResponseDTO):
    data = graphene.Field(RoleSingleDataType)

class RoleListDTO(BaseResponseDTO):
    data = graphene.List(RoleType)

class UserRoleListDTO(BaseResponseDTO):
    data = graphene.List(UserRoleType)

class UserPermissionListDTO(BaseResponseDTO):
    data = graphene.List(UserPermissionType)

class UserAuthorizationDetailsType(graphene.ObjectType):
    """Comprehensive authorization details for a user."""
    roles = graphene.List(RoleType)
    explicit_permissions = graphene.List(UserPermissionType)
    all_permission_codes = graphene.List(graphene.String)

class UserAuthorizationDetailsDTO(BaseResponseDTO):
    data = graphene.Field(UserAuthorizationDetailsType)

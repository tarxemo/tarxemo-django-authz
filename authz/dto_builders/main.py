from authz.models import Permission, Role, UserRole, UserPermission
from authz.dto import PermissionType, RoleType, UserRoleType, UserPermissionType

class PermissionDTOBuilder:
    @staticmethod
    def from_model(permission: Permission) -> PermissionType:
        if not permission:
            return None
        return PermissionType(
            id=permission.id,
            code=permission.code,
            description=permission.description,
            is_active=permission.is_active,
            created_at=permission.created_at,
            updated_at=permission.updated_at
        )

class RoleDTOBuilder:
    @staticmethod
    def from_model(role: Role) -> RoleType:
        if not role:
            return None
        
        # We need to handle permission_codes efficiently
        # Ideally this should be prefetched
        permission_codes = []
        if hasattr(role, 'prefetched_permission_codes'):
            permission_codes = role.prefetched_permission_codes
        else:
             permission_codes = list(role.permissions.filter(is_active=True).values_list('code', flat=True))

        return RoleType(
            id=role.id,
            name=role.name,
            description=role.description,
            is_active=role.is_active,
            created_at=role.created_at,
            updated_at=role.updated_at,
            permission_codes=permission_codes
        )

class UserRoleDTOBuilder:
    @staticmethod
    def from_model(user_role: UserRole) -> UserRoleType:
        if not user_role:
            return None
        return UserRoleType(
            id=user_role.id,
            role=RoleDTOBuilder.from_model(user_role.role),
            user_id=user_role.user_id,
            created_at=user_role.created_at
        )

class UserPermissionDTOBuilder:
    @staticmethod
    def from_model(user_permission: UserPermission) -> UserPermissionType:
        if not user_permission:
            return None
        return UserPermissionType(
            id=user_permission.id,
            permission=PermissionDTOBuilder.from_model(user_permission.permission),
            user_id=user_permission.user_id,
            allow=user_permission.allow,
            created_at=user_permission.created_at
        )

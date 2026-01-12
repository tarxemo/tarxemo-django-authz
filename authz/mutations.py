import graphene
from django.db import transaction
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from tarxemo_django_graphene_utils import build_error, build_success_response

from authz.models import Permission, Role, UserRole, UserPermission
from authz.services import (
    assign_role, revoke_role, grant_permission, deny_permission, revoke_user_permission
)
from authz.utils import validate_permission_code
from authz.dto.types import (
    PermissionInput, PermissionUpdateInput, PermissionSingleDTO,
    RoleInput, RoleUpdateInput, RoleSingleDTO,
    AssignRoleInput, RevokeRoleInput, StandardResponseType,
    GrantPermissionInput, DenyPermissionInput, RevokeUserPermissionInput
)
from authz.dto_builders import (
    PermissionDTOBuilder, RoleDTOBuilder
)

User = get_user_model()

# -----------------------------------------------------------------------------
# Permission Mutations
# -----------------------------------------------------------------------------

class CreatePermission(graphene.Mutation):
    class Arguments:
        input = PermissionInput(required=True)
    
    Output = PermissionSingleDTO
    
    @transaction.atomic
    def mutate(self, info, input):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                 return PermissionSingleDTO(response=build_error("Permission denied"))
            
            # Validate code format
            validate_permission_code(input.code)
            
            if Permission.objects.filter(code=input.code).exists():
                 return PermissionSingleDTO(response=build_error("Permission code already exists"))
            
            permission = Permission.objects.create(
                code=input.code,
                description=input.description or ""
            )
            
            return PermissionSingleDTO(
                data=PermissionSingleDataType(permission=PermissionDTOBuilder.from_model(permission)),
                response=build_success_response("Permission created successfully")
            )
        except Exception as e:
            return PermissionSingleDTO(response=build_error(str(e)))

class UpdatePermission(graphene.Mutation):
    class Arguments:
        input = PermissionUpdateInput(required=True)
        
    Output = PermissionSingleDTO
    
    @transaction.atomic
    def mutate(self, info, input):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                 return PermissionSingleDTO(response=build_error("Permission denied"))
            
            try:
                permission = Permission.objects.get(id=input.id)
            except Permission.DoesNotExist:
                return PermissionSingleDTO(response=build_error("Permission not found"))
            
            if input.description is not None:
                permission.description = input.description
            
            if input.is_active is not None:
                permission.is_active = input.is_active
                
            permission.save()
            
            return PermissionSingleDTO(
                data=PermissionSingleDataType(permission=PermissionDTOBuilder.from_model(permission)),
                response=build_success_response("Permission updated successfully")
            )
        except Exception as e:
            return PermissionSingleDTO(response=build_error(str(e)))

class DeletePermission(graphene.Mutation):
    class Arguments:
        id = graphene.ID(required=True)
        
    Output = StandardResponseType
    
    @transaction.atomic
    def mutate(self, info, id):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                return StandardResponseType(response=build_error("Permission denied"))
                
            try:
                permission = Permission.objects.get(id=id)
                permission.delete()
                return StandardResponseType(response=build_success_response("Permission deleted successfully"))
            except Permission.DoesNotExist:
                return StandardResponseType(response=build_error("Permission not found"))
                
        except Exception as e:
            return StandardResponseType(response=build_error(str(e)))

# -----------------------------------------------------------------------------
# Role Mutations
# -----------------------------------------------------------------------------

class CreateRole(graphene.Mutation):
    class Arguments:
        input = RoleInput(required=True)
        
    Output = RoleSingleDTO
    
    @transaction.atomic
    def mutate(self, info, input):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                 return RoleSingleDTO(response=build_error("Permission denied"))
            
            if Role.objects.filter(name=input.name).exists():
                 return RoleSingleDTO(response=build_error("Role name already exists"))
            
            role = Role.objects.create(
                name=input.name,
                description=input.description or ""
            )
            
            if input.permission_codes:
                for code in input.permission_codes:
                    try:
                        role.add_permission(code)
                    except Permission.DoesNotExist:
                        pass # Ignore invalid codes
            
            return RoleSingleDTO(
                data=RoleSingleDataType(role=RoleDTOBuilder.from_model(role)),
                response=build_success_response("Role created successfully")
            )
        except Exception as e:
            return RoleSingleDTO(response=build_error(str(e)))

class UpdateRole(graphene.Mutation):
    class Arguments:
        input = RoleUpdateInput(required=True)
        
    Output = RoleSingleDTO
    
    @transaction.atomic
    def mutate(self, info, input):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                 return RoleSingleDTO(response=build_error("Permission denied"))
            
            try:
                role = Role.objects.get(id=input.id)
            except Role.DoesNotExist:
                return RoleSingleDTO(response=build_error("Role not found"))
            
            if input.name:
                if Role.objects.filter(name=input.name).exclude(id=input.id).exists():
                    return RoleSingleDTO(response=build_error("Role name already exists"))
                role.name = input.name
                
            if input.description is not None:
                role.description = input.description
                
            if input.is_active is not None:
                role.is_active = input.is_active

            if input.permission_codes is not None:
                # Update permissions
                role.permissions.clear()
                for code in input.permission_codes:
                    try:
                        role.add_permission(code)
                    except Permission.DoesNotExist:
                        pass
                
            role.save()
            
            return RoleSingleDTO(
                data=RoleSingleDataType(role=RoleDTOBuilder.from_model(role)),
                response=build_success_response("Role updated successfully")
            )
        except Exception as e:
            return RoleSingleDTO(response=build_error(str(e)))

class DeleteRole(graphene.Mutation):
    class Arguments:
        id = graphene.ID(required=True)
        
    Output = StandardResponseType
    
    @transaction.atomic
    def mutate(self, info, id):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                return StandardResponseType(response=build_error("Permission denied"))
                
            try:
                role = Role.objects.get(id=id)
                role.delete()
                return StandardResponseType(response=build_success_response("Role deleted successfully"))
            except Role.DoesNotExist:
                return StandardResponseType(response=build_error("Role not found"))
                 
        except Exception as e:
            return StandardResponseType(response=build_error(str(e)))

# -----------------------------------------------------------------------------
# Assignment Mutations
# -----------------------------------------------------------------------------

class AssignRole(graphene.Mutation):
    class Arguments:
        input = AssignRoleInput(required=True)
        
    Output = StandardResponseType
    
    @transaction.atomic
    def mutate(self, info, input):
        try:
            # Check permission (superuser only for now)
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                 return StandardResponseType(response=build_error("Permission denied"))
            
            try:
                target_user = User.objects.get(id=input.user_id)
            except User.DoesNotExist:
                 return StandardResponseType(response=build_error("User not found"))
            
            assign_role(target_user, input.role_name, created_by=user)
            
            return StandardResponseType(response=build_success_response("Role assigned successfully"))
        except Exception as e:
            return StandardResponseType(response=build_error(str(e)))

class RevokeRole(graphene.Mutation):
    class Arguments:
        input = RevokeRoleInput(required=True)
        
    Output = StandardResponseType
    
    @transaction.atomic
    def mutate(self, info, input):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                 return StandardResponseType(response=build_error("Permission denied"))
            
            try:
                target_user = User.objects.get(id=input.user_id)
            except User.DoesNotExist:
                 return StandardResponseType(response=build_error("User not found"))
            
            result = revoke_role(target_user, input.role_name)
            
            if result:
                return StandardResponseType(response=build_success_response("Role revoked successfully"))
            else:
                return StandardResponseType(response=build_error("Role assignment not found"))
        except Exception as e:
            return StandardResponseType(response=build_error(str(e)))

class GrantPermission(graphene.Mutation):
    class Arguments:
        input = GrantPermissionInput(required=True)
    
    Output = StandardResponseType
    
    @transaction.atomic
    def mutate(self, info, input):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                 return StandardResponseType(response=build_error("Permission denied"))
            
            try:
                target_user = User.objects.get(id=input.user_id)
            except User.DoesNotExist:
                 return StandardResponseType(response=build_error("User not found"))
                 
            grant_permission(target_user, input.permission_code, created_by=user)
            
            return StandardResponseType(response=build_success_response("Permission granted successfully"))
        except Exception as e:
            return StandardResponseType(response=build_error(str(e)))

class DenyPermission(graphene.Mutation):
    class Arguments:
        input = DenyPermissionInput(required=True)
    
    Output = StandardResponseType
    
    @transaction.atomic
    def mutate(self, info, input):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                 return StandardResponseType(response=build_error("Permission denied"))
            
            try:
                target_user = User.objects.get(id=input.user_id)
            except User.DoesNotExist:
                 return StandardResponseType(response=build_error("User not found"))
                 
            deny_permission(target_user, input.permission_code, created_by=user)
            
            return StandardResponseType(response=build_success_response("Permission denied successfully"))
        except Exception as e:
            return StandardResponseType(response=build_error(str(e)))

class RevokeUserPermission(graphene.Mutation):
    class Arguments:
        input = RevokeUserPermissionInput(required=True)
        
    Output = StandardResponseType
    
    @transaction.atomic
    def mutate(self, info, input):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                 return StandardResponseType(response=build_error("Permission denied"))
            
            try:
                target_user = User.objects.get(id=input.user_id)
            except User.DoesNotExist:
                 return StandardResponseType(response=build_error("User not found"))
                 
            result = revoke_user_permission(target_user, input.permission_code)
            
            if result:
                 return StandardResponseType(response=build_success_response("Permission override revoked successfully"))
            else:
                 return StandardResponseType(response=build_error("Permission override not found"))
        except Exception as e:
            return StandardResponseType(response=build_error(str(e)))

# -----------------------------------------------------------------------------
# Mutation Class
# -----------------------------------------------------------------------------

from authz.dto.types import PermissionSingleDataType, RoleSingleDataType

class AuthzMutation(graphene.ObjectType):
    create_permission = CreatePermission.Field()
    update_permission = UpdatePermission.Field()
    delete_permission = DeletePermission.Field()
    
    create_role = CreateRole.Field()
    update_role = UpdateRole.Field()  # Typo fix: UpdateRole
    delete_role = DeleteRole.Field()
    
    assign_role = AssignRole.Field()
    revoke_role = RevokeRole.Field()
    
    grant_permission = GrantPermission.Field()
    deny_permission = DenyPermission.Field()
    revoke_user_permission = RevokeUserPermission.Field()


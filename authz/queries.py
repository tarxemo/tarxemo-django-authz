import graphene
from django.db.models import Q
from django.contrib.auth import get_user_model
from tarxemo_django_graphene_utils import build_success_response, build_error

from authz.models import Permission, Role, UserRole, UserPermission
from authz.dto.types import (
    PermissionListDTO, RoleListDTO, RoleSingleDTO,
    UserAuthorizationDetailsDTO, UserAuthorizationDetailsType
)
from authz.dto_builders import PermissionDTOBuilder, RoleDTOBuilder, UserPermissionDTOBuilder

User = get_user_model()

class AuthzQuery(graphene.ObjectType):
    
    permissions = graphene.Field(
        PermissionListDTO,
        search=graphene.String(),
        page=graphene.Int(),
        page_size=graphene.Int()
    )
    
    roles = graphene.Field(
        RoleListDTO,
        search=graphene.String(),
        page=graphene.Int(),
        page_size=graphene.Int()
    )
    
    role = graphene.Field(
        RoleSingleDTO,
        id=graphene.UUID(required=True)
    )
    
    user_authorization_details = graphene.Field(
        UserAuthorizationDetailsDTO,
        user_id=graphene.ID(required=True)
    )

    def resolve_permissions(self, info, search=None, page=1, page_size=20):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                return PermissionListDTO(response=build_error("Permission denied"))
            
            qs = Permission.objects.filter(is_active=True)
            
            if search:
                qs = qs.filter(
                    Q(code__icontains=search) | 
                    Q(description__icontains=search)
                )
            
            qs = qs.order_by('code')
            
            # Simple pagination
            start = (page - 1) * page_size
            end = start + page_size
            
            # Using DTO builder
            permissions = [PermissionDTOBuilder.from_model(p) for p in qs[start:end]]
            
            return PermissionListDTO(
                data=permissions,
                response=build_success_response("Permissions fetched successfully")
            )
        except Exception as e:
            return PermissionListDTO(response=build_error(str(e)))

    def resolve_roles(self, info, search=None, page=1, page_size=20):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                 return RoleListDTO(response=build_error("Permission denied"))
            
            qs = Role.objects.filter(is_active=True).prefetch_related('permissions')
            
            if search:
                qs = qs.filter(
                    Q(name__icontains=search) | 
                    Q(description__icontains=search)
                )
            
            qs = qs.order_by('name')
            
            start = (page - 1) * page_size
            end = start + page_size
            
            roles = [RoleDTOBuilder.from_model(r) for r in qs[start:end]]
            
            return RoleListDTO(
                data=roles,
                response=build_success_response("Roles fetched successfully")
            )
        except Exception as e:
            return RoleListDTO(response=build_error(str(e)))
            
    def resolve_role(self, info, id):
        try:
            user = info.context.user
            if not user.is_authenticated or not user.is_superuser:
                 return RoleSingleDTO(response=build_error("Permission denied"))
            
            role = Role.objects.get(id=id)
            
            from authz.dto.types import RoleSingleDataType
            return RoleSingleDTO(
                data=RoleSingleDataType(role=RoleDTOBuilder.from_model(role)),
                response=build_success_response("Role fetched successfully")
            )
        except Role.DoesNotExist:
            return RoleSingleDTO(response=build_error("Role not found"))
        except Exception as e:
            return RoleSingleDTO(response=build_error(str(e)))

    def resolve_user_authorization_details(self, info, user_id):
        try:
            actor = info.context.user
            if not actor.is_authenticated:
                 return UserAuthorizationDetailsDTO(response=build_error("Authentication required"))
            
            # Allow user to see their own details, or superuser to see anyone's
            if str(actor.id) != str(user_id) and not actor.is_superuser:
                return UserAuthorizationDetailsDTO(response=build_error("Permission denied"))
                
            try:
                target_user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return UserAuthorizationDetailsDTO(response=build_error("User not found"))
            
            # Get roles
            user_roles = UserRole.objects.filter(user=target_user).select_related('role')
            roles_data = [RoleDTOBuilder.from_model(ur.role) for ur in user_roles]
            
            # Get explicit permissions
            user_perms = UserPermission.objects.filter(user=target_user).select_related('permission')
            perms_data = [UserPermissionDTOBuilder.from_model(up) for up in user_perms]
            
            # Get effective permissions (codes)
            from authz.engine import get_user_permission_codes
            all_codes = list(get_user_permission_codes(target_user))
            
            details = UserAuthorizationDetailsType(
                roles=roles_data,
                explicit_permissions=perms_data,
                all_permission_codes=all_codes
            )
            
            return UserAuthorizationDetailsDTO(
                data=details,
                response=build_success_response("User authorization details fetched")
            )
        except Exception as e:
            return UserAuthorizationDetailsDTO(response=build_error(str(e)))

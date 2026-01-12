"""
Comprehensive tests for the authorization framework.

Run with: python manage.py test authz
"""

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from authz.models import Permission, Role, UserRole, UserPermission
from authz.engine import authorize
from authz.policies import BasePolicy, policy_registry, register_policy
from authz.services import (
    assign_role, revoke_role, grant_permission, deny_permission,
    get_user_roles, get_permission_matrix
)
from authz.utils import validate_permission_code, parse_permission_code
from authz.exceptions import InvalidPermissionCode


User = get_user_model()


class PermissionModelTest(TestCase):
    """Test Permission model."""
    
    def test_create_permission(self):
        """Test creating a valid permission."""
        perm = Permission.objects.create(
            code="courses.enroll",
            description="Enroll in a course"
        )
        self.assertEqual(perm.code, "courses.enroll")
        self.assertTrue(perm.is_active)
    
    def test_permission_validation(self):
        """Test permission code validation."""
        # Invalid: no dot
        with self.assertRaises(ValidationError):
            perm = Permission(code="invalid")
            perm.full_clean()
    
    def test_permission_str(self):
        """Test permission string representation."""
        perm = Permission.objects.create(code="test.permission")
        self.assertEqual(str(perm), "test.permission")


class RoleModelTest(TestCase):
    """Test Role model."""
    
    def setUp(self):
        self.perm1 = Permission.objects.create(code="courses.view")
        self.perm2 = Permission.objects.create(code="courses.enroll")
    
    def test_create_role(self):
        """Test creating a role."""
        role = Role.objects.create(
            name="Student",
            description="Student role"
        )
        self.assertEqual(role.name, "Student")
        self.assertTrue(role.is_active)
    
    def test_add_permissions_to_role(self):
        """Test adding permissions to a role."""
        role = Role.objects.create(name="Student")
        role.permissions.add(self.perm1, self.perm2)
        
        self.assertEqual(role.permissions.count(), 2)
        self.assertIn("courses.view", role.get_permission_codes())
        self.assertIn("courses.enroll", role.get_permission_codes())
    
    def test_role_add_permission_by_code(self):
        """Test adding permission by code."""
        role = Role.objects.create(name="Student")
        role.add_permission("courses.view")
        
        self.assertEqual(role.permissions.count(), 1)


class AuthorizationEngineTest(TestCase):
    """Test the authorization engine."""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            password="testpass"
        )
        self.superuser = User.objects.create_superuser(
            username="admin",
            password="adminpass"
        )
        
        self.perm_view = Permission.objects.create(code="courses.view")
        self.perm_enroll = Permission.objects.create(code="courses.enroll")
        self.perm_delete = Permission.objects.create(code="courses.delete")
        
        self.student_role = Role.objects.create(name="Student")
        self.student_role.permissions.add(self.perm_view, self.perm_enroll)
    
    def test_superuser_has_all_permissions(self):
        """Test that superusers bypass all checks."""
        self.assertTrue(authorize(self.superuser, "courses.view"))
        self.assertTrue(authorize(self.superuser, "courses.delete"))
        self.assertTrue(authorize(self.superuser, "any.permission"))
    
    def test_anonymous_user_denied(self):
        """Test that anonymous users are denied by default."""
        from django.contrib.auth.models import AnonymousUser
        anon = AnonymousUser()
        self.assertFalse(authorize(anon, "courses.view"))
    
    def test_role_based_permission(self):
        """Test role-based permission checking."""
        UserRole.objects.create(user=self.user, role=self.student_role)
        
        self.assertTrue(authorize(self.user, "courses.view"))
        self.assertTrue(authorize(self.user, "courses.enroll"))
        self.assertFalse(authorize(self.user, "courses.delete"))
    
    def test_explicit_allow(self):
        """Test explicit user permission allow."""
        UserPermission.objects.create(
            user=self.user,
            permission=self.perm_delete,
            allow=True
        )
        
        self.assertTrue(authorize(self.user, "courses.delete"))
    
    def test_explicit_deny_overrides_role(self):
        """Test that explicit deny overrides role permissions."""
        UserRole.objects.create(user=self.user, role=self.student_role)
        UserPermission.objects.create(
            user=self.user,
            permission=self.perm_view,
            allow=False
        )
        
        # User has role with courses.view, but explicit deny overrides
        self.assertFalse(authorize(self.user, "courses.view"))
    
    def test_no_permission_by_default(self):
        """Test that users have no permissions by default."""
        self.assertFalse(authorize(self.user, "courses.view"))
        self.assertFalse(authorize(self.user, "courses.enroll"))


class PolicySystemTest(TestCase):
    """Test the policy system."""
    
    def setUp(self):
        self.user = User.objects.create_user(username="testuser")
        self.perm = Permission.objects.create(code="test.action")
        
        # Clear any existing policies
        policy_registry.clear()
    
    def test_policy_registration(self):
        """Test registering a policy."""
        class TestPolicy(BasePolicy):
            permission_code = "test.action"
            
            def allows(self, user, obj=None, context=None):
                return True
        
        policy_registry.register(TestPolicy)
        policies = policy_registry.get_policies("test.action")
        self.assertEqual(len(policies), 1)
    
    def test_policy_evaluation(self):
        """Test policy evaluation."""
        class AlwaysAllowPolicy(BasePolicy):
            permission_code = "test.action"
            
            def allows(self, user, obj=None, context=None):
                return True
        
        policy_registry.register(AlwaysAllowPolicy)
        
        # Policy allows, so authorization should succeed
        # (assuming no other restrictions)
        allowed, reason = policy_registry.evaluate_policies(
            self.user, "test.action"
        )
        self.assertTrue(allowed)
    
    def test_policy_deny(self):
        """Test policy denial."""
        class AlwaysDenyPolicy(BasePolicy):
            permission_code = "test.action"
            
            def allows(self, user, obj=None, context=None):
                return False
        
        policy_registry.register(AlwaysDenyPolicy)
        
        allowed, reason = policy_registry.evaluate_policies(
            self.user, "test.action"
        )
        self.assertFalse(allowed)
        self.assertIsNotNone(reason)
    
    def test_register_policy_decorator(self):
        """Test @register_policy decorator."""
        @register_policy
        class DecoratedPolicy(BasePolicy):
            permission_code = "test.decorated"
            
            def allows(self, user, obj=None, context=None):
                return True
        
        policies = policy_registry.get_policies("test.decorated")
        self.assertEqual(len(policies), 1)


class ServiceLayerTest(TestCase):
    """Test the service layer functions."""
    
    def setUp(self):
        self.user = User.objects.create_user(username="testuser")
        self.admin = User.objects.create_user(username="admin")
        
        self.perm = Permission.objects.create(code="test.permission")
        self.role = Role.objects.create(name="TestRole")
        self.role.permissions.add(self.perm)
    
    def test_assign_role(self):
        """Test assigning a role to a user."""
        assign_role(self.user, "TestRole", created_by=self.admin)
        
        self.assertTrue(UserRole.objects.filter(
            user=self.user,
            role=self.role
        ).exists())
    
    def test_revoke_role(self):
        """Test revoking a role from a user."""
        assign_role(self.user, "TestRole")
        result = revoke_role(self.user, "TestRole")
        
        self.assertTrue(result)
        self.assertFalse(UserRole.objects.filter(
            user=self.user,
            role=self.role
        ).exists())
    
    def test_grant_permission(self):
        """Test granting a permission to a user."""
        grant_permission(self.user, "test.permission", created_by=self.admin)
        
        self.assertTrue(UserPermission.objects.filter(
            user=self.user,
            permission=self.perm,
            allow=True
        ).exists())
    
    def test_deny_permission(self):
        """Test denying a permission for a user."""
        deny_permission(self.user, "test.permission", created_by=self.admin)
        
        self.assertTrue(UserPermission.objects.filter(
            user=self.user,
            permission=self.perm,
            allow=False
        ).exists())
    
    def test_get_user_roles(self):
        """Test getting user roles."""
        assign_role(self.user, "TestRole")
        roles = get_user_roles(self.user)
        
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].name, "TestRole")
    
    def test_get_permission_matrix(self):
        """Test getting permission matrix for a user."""
        assign_role(self.user, "TestRole")
        matrix = get_permission_matrix(self.user)
        
        self.assertEqual(matrix['user'], self.user)
        self.assertIn("TestRole", matrix['roles'])
        self.assertIn("test.permission", matrix['all_permissions'])


class UtilityFunctionsTest(TestCase):
    """Test utility functions."""
    
    def test_validate_permission_code_valid(self):
        """Test validating valid permission codes."""
        self.assertTrue(validate_permission_code("courses.view"))
        self.assertTrue(validate_permission_code("courses.enrollment.create"))
    
    def test_validate_permission_code_invalid(self):
        """Test validating invalid permission codes."""
        with self.assertRaises(InvalidPermissionCode):
            validate_permission_code("invalid")
        
        with self.assertRaises(InvalidPermissionCode):
            validate_permission_code(".invalid")
        
        with self.assertRaises(InvalidPermissionCode):
            validate_permission_code("invalid.")
    
    def test_parse_permission_code(self):
        """Test parsing permission codes."""
        namespace, action, resource = parse_permission_code("courses.view")
        self.assertEqual(namespace, "courses")
        self.assertEqual(action, "view")
        self.assertIsNone(resource)
        
        namespace, action, resource = parse_permission_code("courses.enrollment.create")
        self.assertEqual(namespace, "courses")
        self.assertEqual(action, "create")
        self.assertEqual(resource, "enrollment")


class IntegrationTest(TestCase):
    """Integration tests for complete workflows."""
    
    def setUp(self):
        # Create users
        self.student = User.objects.create_user(username="student")
        self.instructor = User.objects.create_user(username="instructor")
        self.admin = User.objects.create_user(username="admin")
        
        # Create permissions
        self.perm_view = Permission.objects.create(code="courses.view")
        self.perm_enroll = Permission.objects.create(code="courses.enroll")
        self.perm_grade = Permission.objects.create(code="courses.grade")
        self.perm_manage = Permission.objects.create(code="courses.manage")
        
        # Create roles
        self.student_role = Role.objects.create(name="Student")
        self.student_role.permissions.add(self.perm_view, self.perm_enroll)
        
        self.instructor_role = Role.objects.create(name="Instructor")
        self.instructor_role.permissions.add(
            self.perm_view, self.perm_grade, self.perm_manage
        )
        
        # Assign roles
        assign_role(self.student, "Student")
        assign_role(self.instructor, "Instructor")
    
    def test_student_permissions(self):
        """Test student can view and enroll but not grade."""
        self.assertTrue(authorize(self.student, "courses.view"))
        self.assertTrue(authorize(self.student, "courses.enroll"))
        self.assertFalse(authorize(self.student, "courses.grade"))
        self.assertFalse(authorize(self.student, "courses.manage"))
    
    def test_instructor_permissions(self):
        """Test instructor can view, grade, and manage but not enroll."""
        self.assertTrue(authorize(self.instructor, "courses.view"))
        self.assertFalse(authorize(self.instructor, "courses.enroll"))
        self.assertTrue(authorize(self.instructor, "courses.grade"))
        self.assertTrue(authorize(self.instructor, "courses.manage"))
    
    def test_permission_override(self):
        """Test that explicit permissions override role permissions."""
        # Give student explicit permission to grade
        grant_permission(self.student, "courses.grade")
        self.assertTrue(authorize(self.student, "courses.grade"))
        
        # Deny instructor's view permission
        deny_permission(self.instructor, "courses.view")
        self.assertFalse(authorize(self.instructor, "courses.view"))

import json
from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from graphene.test import Client
import graphene

from authz.schema import AuthzQuery, AuthzMutation
from authz.models import Permission, Role, UserRole

User = get_user_model()

class TestSchema(AuthzQuery, AuthzMutation, graphene.ObjectType):
    pass

schema = graphene.Schema(query=TestSchema, mutation=TestSchema)

class GraphQLTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_superuser(username='admin', password='password')
        self.client = Client(schema)
        self.factory = RequestFactory()
        
    def execute_query(self, query, variables=None):
        request = self.factory.get('/')
        request.user = self.user
        return self.client.execute(query, variable_values=variables, context_value=request)

    def test_create_permission(self):
        mutation = """
            mutation CreatePermission($input: PermissionInput!) {
                createPermission(input: $input) {
                    response {
                        message
                    }
                    data {
                        permission {
                            code
                            description
                        }
                    }
                }
            }
        """
        variables = {
            "input": {
                "code": "test.permission",
                "description": "Test Permission"
            }
        }
        
        result = self.execute_query(mutation, variables)
        if 'errors' in result:
            print(result['errors'])
        self.assertEqual(result['data']['createPermission']['response']['message'], "Permission created successfully")
        self.assertEqual(result['data']['createPermission']['data']['permission']['code'], "test.permission")
        self.assertTrue(Permission.objects.filter(code="test.permission").exists())

    def test_create_role(self):
        # First create a permission
        Permission.objects.create(code="role.view")  # Fixed validation error
        
        mutation = """
            mutation CreateRole($input: RoleInput!) {
                createRole(input: $input) {
                    response {
                        message
                    }
                    data {
                        role {
                            name
                            permissionCodes
                        }
                    }
                }
            }
        """
        variables = {
            "input": {
                "name": "Test Role",
                "permissionCodes": ["role.view"]
            }
        }
        
        result = self.execute_query(mutation, variables)
        if 'errors' in result:
            print(result['errors'])
            
        self.assertEqual(result['data']['createRole']['response']['message'], "Role created successfully")
        self.assertEqual(result['data']['createRole']['data']['role']['name'], "Test Role")
        self.assertIn("role.view", result['data']['createRole']['data']['role']['permissionCodes'])

    def test_assign_role(self):
        target_user = User.objects.create_user(username='target')
        Role.objects.create(name="AssignedRole")
        
        mutation = """
            mutation AssignRole($input: AssignRoleInput!) {
                assignRole(input: $input) {
                    response {
                        message
                    }
                }
            }
        """
        variables = {
            "input": {
                "userId": str(target_user.id),
                "roleName": "AssignedRole"
            }
        }
        
        result = self.execute_query(mutation, variables)
        if 'errors' in result:
            print(result['errors'])
        self.assertEqual(result['data']['assignRole']['response']['message'], "Role assigned successfully")
        self.assertTrue(UserRole.objects.filter(user=target_user, role__name="AssignedRole").exists())

    def test_query_permissions(self):
        Permission.objects.create(code="app.read")
        Permission.objects.create(code="app.write")
        
        query = """
            query {
                permissions {
                    data {
                        code
                    }
                    response {
                        message
                    }
                }
            }
        """
        
        result = self.execute_query(query)
        if 'errors' in result:
            print(result['errors'])
        self.assertEqual(result['data']['permissions']['response']['message'], "Permissions fetched successfully")
        codes = [p['code'] for p in result['data']['permissions']['data']]
        self.assertIn("app.read", codes)
        self.assertIn("app.write", codes)

from django.core.management.base import BaseCommand
from django.db import transaction
from django.contrib.auth import get_user_model
from authz.models import Permission, Role
from authz.services import assign_role

User = get_user_model()

class Command(BaseCommand):
    help = 'Seeds initial RBAC permissions and roles'

    def handle(self, *args, **options):
        self.stdout.write('Seeding RBAC data...')
        
        # 1. Define Permissions
        permissions_map = {
            'properties': [
                ('properties.view', 'View properties'),
                ('properties.create', 'Create new properties'),
                ('properties.update', 'Update own properties'),
                ('properties.delete', 'Delete own properties'),
                ('properties.approve', 'Approve property listings (Admin)'),
                ('properties.amenities.manage', 'Manage property amenities (Admin)'),
            ],
            'bookings': [
                ('bookings.view', 'View bookings'),
                ('bookings.create', 'Create new bookings'),
                ('bookings.cancel', 'Cancel bookings'),
                ('bookings.approve', 'Approve bookings'),
            ],
            'users': [
                ('users.view', 'View users'),
                ('users.update', 'Update users'),
                ('users.verify', 'Verify user identity (Admin)'),
                ('users.ban', 'Ban users (Admin)'),
            ],
            'authz': [
                ('authz.manage', 'Manage roles and permissions (Admin)'),
            ]
        }
        
        all_perms = []
        created_count = 0
        
        with transaction.atomic():
            for category, perms in permissions_map.items():
                for code, desc in perms:
                    perm, created = Permission.objects.get_or_create(
                        code=code,
                        defaults={'description': desc}
                    )
                    all_perms.append(perm)
                    if created:
                        created_count += 1
            
            self.stdout.write(self.style.SUCCESS(f'Created {created_count} permissions'))
            
            # 2. Define Roles
            
            # Super Admin
            super_admin, _ = Role.objects.get_or_create(
                name='Super Admin',
                defaults={'description': 'Full system access'}
            )
            super_admin.permissions.set(all_perms)
            
            # Property Owner
            owner, _ = Role.objects.get_or_create(
                name='Property Owner',
                defaults={'description': 'Manage own properties and bookings'}
            )
            owner_perms = Permission.objects.filter(code__in=[
                'properties.view', 'properties.create', 'properties.update', 'properties.delete',
                'bookings.view', 'bookings.approve'
            ])
            owner.permissions.set(owner_perms)
            
            # Customer
            customer, _ = Role.objects.get_or_create(
                name='Customer',
                defaults={'description': 'Standard user access'}
            )
            customer.permissions.set(Permission.objects.filter(code__in=[
                'properties.view', 'bookings.create', 'bookings.view', 'bookings.cancel'
            ]))
            
            self.stdout.write(self.style.SUCCESS('Roles updated: Super Admin, Property Owner, Customer'))
            
            # 3. Assign Role to Superuser
            superusers = User.objects.filter(is_superuser=True)
            for su in superusers:
                assign_role(su, 'Super Admin', created_by=su)
                self.stdout.write(f'Assigned Super Admin to {su.email}')

        self.stdout.write(self.style.SUCCESS('RBAC seeding completed successfully!'))

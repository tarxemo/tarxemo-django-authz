"""
Template tags for permission checks in Django templates.

Load these tags in your template with:
    {% load authz_tags %}
"""

from django import template
from django.template import Node, TemplateSyntaxError

from authz.engine import authorize


register = template.Library()


@register.simple_tag(takes_context=True)
def has_permission(context, permission_code, obj=None):
    """
    Check if the current user has a permission.
    
    Usage in template:
        {% load authz_tags %}
        {% has_permission 'courses.enroll' as can_enroll %}
        {% if can_enroll %}
            <button>Enroll</button>
        {% endif %}
        
        Or with an object:
        {% has_permission 'documents.edit' document as can_edit %}
    
    Args:
        context: Template context
        permission_code: Permission code to check
        obj: Optional object to check permission against
        
    Returns:
        bool: True if user has permission
    """
    request = context.get('request')
    if not request:
        return False
    
    user = getattr(request, 'user', None)
    if not user:
        return False
    
    return authorize(user, permission_code, obj)


@register.filter
def has_perm(user, permission_code):
    """
    Filter to check if a user has a permission.
    
    Usage in template:
        {% load authz_tags %}
        {% if user|has_perm:'courses.enroll' %}
            <button>Enroll</button>
        {% endif %}
    
    Args:
        user: User object
        permission_code: Permission code to check
        
    Returns:
        bool: True if user has permission
    """
    if not user or not user.is_authenticated:
        return False
    
    return authorize(user, permission_code)


@register.simple_tag(takes_context=True)
def check_permission(context, user, permission_code, obj=None):
    """
    Check if a specific user has a permission.
    
    This is useful when checking permissions for users other than
    the current request user.
    
    Usage in template:
        {% load authz_tags %}
        {% check_permission instructor 'courses.grade' course as can_grade %}
    
    Args:
        context: Template context
        user: User to check
        permission_code: Permission code to check
        obj: Optional object to check permission against
        
    Returns:
        bool: True if user has permission
    """
    if not user or not user.is_authenticated:
        return False
    
    return authorize(user, permission_code, obj)


@register.simple_tag(takes_context=True)
def has_any_permission(context, *permission_codes, obj=None):
    """
    Check if user has ANY of the specified permissions.
    
    Usage in template:
        {% load authz_tags %}
        {% has_any_permission 'courses.edit' 'courses.admin' as can_manage %}
    
    Args:
        context: Template context
        *permission_codes: Permission codes to check
        obj: Optional object to check permission against
        
    Returns:
        bool: True if user has any of the permissions
    """
    request = context.get('request')
    if not request:
        return False
    
    user = getattr(request, 'user', None)
    if not user or not user.is_authenticated:
        return False
    
    return any(
        authorize(user, perm_code, obj)
        for perm_code in permission_codes
    )


@register.simple_tag(takes_context=True)
def has_all_permissions(context, *permission_codes, obj=None):
    """
    Check if user has ALL of the specified permissions.
    
    Usage in template:
        {% load authz_tags %}
        {% has_all_permissions 'courses.view' 'courses.enroll' as can_enroll %}
    
    Args:
        context: Template context
        *permission_codes: Permission codes to check
        obj: Optional object to check permission against
        
    Returns:
        bool: True if user has all permissions
    """
    request = context.get('request')
    if not request:
        return False
    
    user = getattr(request, 'user', None)
    if not user or not user.is_authenticated:
        return False
    
    return all(
        authorize(user, perm_code, obj)
        for perm_code in permission_codes
    )


class IfHasPermissionNode(Node):
    """
    Node for {% if_has_permission %} block tag.
    """
    
    def __init__(self, permission_code, obj_var, nodelist_true, nodelist_false):
        self.permission_code = permission_code
        self.obj_var = obj_var
        self.nodelist_true = nodelist_true
        self.nodelist_false = nodelist_false
    
    def render(self, context):
        request = context.get('request')
        if not request:
            return self.nodelist_false.render(context)
        
        user = getattr(request, 'user', None)
        if not user or not user.is_authenticated:
            return self.nodelist_false.render(context)
        
        # Resolve permission code
        try:
            permission_code = self.permission_code.resolve(context)
        except template.VariableDoesNotExist:
            permission_code = self.permission_code.var
        
        # Resolve object if provided
        obj = None
        if self.obj_var:
            try:
                obj = self.obj_var.resolve(context)
            except template.VariableDoesNotExist:
                pass
        
        # Check permission
        if authorize(user, permission_code, obj):
            return self.nodelist_true.render(context)
        else:
            return self.nodelist_false.render(context)


@register.tag
def if_has_permission(parser, token):
    """
    Block tag for conditional rendering based on permission.
    
    Usage in template:
        {% load authz_tags %}
        {% if_has_permission 'courses.enroll' %}
            <button>Enroll</button>
        {% else %}
            <p>You cannot enroll</p>
        {% endif_has_permission %}
        
        With object:
        {% if_has_permission 'documents.edit' document %}
            <button>Edit</button>
        {% endif_has_permission %}
    
    Args:
        parser: Template parser
        token: Template token
        
    Returns:
        IfHasPermissionNode: Node for rendering
    """
    bits = token.split_contents()
    
    if len(bits) < 2:
        raise TemplateSyntaxError(
            f"{bits[0]} tag requires at least one argument (permission code)"
        )
    
    permission_code = parser.compile_filter(bits[1])
    
    obj_var = None
    if len(bits) > 2:
        obj_var = parser.compile_filter(bits[2])
    
    nodelist_true = parser.parse(('else', 'endif_has_permission'))
    token = parser.next_token()
    
    if token.contents == 'else':
        nodelist_false = parser.parse(('endif_has_permission',))
        parser.delete_first_token()
    else:
        nodelist_false = template.NodeList()
    
    return IfHasPermissionNode(
        permission_code, obj_var, nodelist_true, nodelist_false
    )

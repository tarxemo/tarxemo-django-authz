"""
Policy system for dynamic, conditional permissions.

Policies allow implementing business rules for authorization that go beyond
simple role-based permissions. For example:
- "A student can enroll in a course ONLY if they are registered for the academic year"
- "Users can only edit their own documents"
- "Access is only allowed during business hours"

Policies are stateless, reusable, and testable.
"""

from typing import Optional, Dict, Any, List, Type
from abc import ABC, abstractmethod
import logging

from .exceptions import PolicyEvaluationError, PolicyRegistrationError


logger = logging.getLogger(__name__)


class BasePolicy(ABC):
    """
    Abstract base class for all authorization policies.
    
    Policies implement custom business rules for permissions.
    Each policy is associated with one or more permission codes.
    
    Example:
        class OwnerOnlyPolicy(BasePolicy):
            permission_code = "documents.edit"
            
            def allows(self, user, obj=None, context=None):
                if obj is None:
                    return False
                return obj.get_owner() == user
    """
    
    # Permission code(s) this policy applies to
    # Can be a string or list of strings
    permission_code: str | List[str] = None
    
    # Optional: Priority for policy evaluation (higher = evaluated first)
    # Default is 0. Use this when order matters.
    priority: int = 0
    
    @abstractmethod
    def allows(self, user, obj=None, context=None) -> bool:
        """
        Evaluate if the user is allowed to perform the action.
        
        This method should be stateless and idempotent.
        
        Args:
            user: The user requesting permission (can be AnonymousUser)
            obj: The object being accessed (optional)
            context: Additional context dict (optional)
            
        Returns:
            bool: True if allowed, False otherwise
            
        Raises:
            PolicyEvaluationError: If evaluation fails unexpectedly
        """
        raise NotImplementedError("Subclasses must implement allows()")
    
    def get_denial_reason(self, user, obj=None, context=None) -> str:
        """
        Return a human-readable reason for denial.
        
        This is optional but helpful for debugging and user feedback.
        
        Args:
            user: The user requesting permission
            obj: The object being accessed (optional)
            context: Additional context dict (optional)
            
        Returns:
            str: Human-readable denial reason
        """
        return f"Permission denied by {self.__class__.__name__}"
    
    def get_permission_codes(self) -> List[str]:
        """
        Get all permission codes this policy applies to.
        
        Returns:
            List[str]: List of permission codes
        """
        if isinstance(self.permission_code, list):
            return self.permission_code
        elif isinstance(self.permission_code, str):
            return [self.permission_code]
        else:
            return []
    
    def __repr__(self):
        return f"<{self.__class__.__name__} for {self.permission_code}>"


class PolicyRegistry:
    """
    Singleton registry for all authorization policies.
    
    Policies are registered here and can be queried by permission code.
    The registry is used by the authorization engine to evaluate policies.
    """
    
    _instance = None
    _policies: Dict[str, List[BasePolicy]] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._policies = {}
        return cls._instance
    
    def register(self, policy_class: Type[BasePolicy]) -> None:
        """
        Register a policy class.
        
        Args:
            policy_class: Policy class (not instance) to register
            
        Raises:
            PolicyRegistrationError: If policy is invalid
        """
        if not issubclass(policy_class, BasePolicy):
            raise PolicyRegistrationError(
                f"{policy_class} must inherit from BasePolicy"
            )
        
        # Instantiate the policy
        try:
            policy = policy_class()
        except Exception as e:
            raise PolicyRegistrationError(
                f"Failed to instantiate {policy_class}: {e}"
            )
        
        # Get permission codes
        permission_codes = policy.get_permission_codes()
        if not permission_codes:
            raise PolicyRegistrationError(
                f"{policy_class} must define permission_code"
            )
        
        # Register for each permission code
        for code in permission_codes:
            if code not in self._policies:
                self._policies[code] = []
            
            # Check for duplicates
            existing_classes = [p.__class__ for p in self._policies[code]]
            if policy_class in existing_classes:
                logger.warning(
                    f"Policy {policy_class.__name__} already registered for {code}"
                )
                continue
            
            self._policies[code].append(policy)
            logger.info(f"Registered policy {policy_class.__name__} for {code}")
        
        # Sort by priority (higher priority first)
        for code in permission_codes:
            self._policies[code].sort(key=lambda p: p.priority, reverse=True)
    
    def get_policies(self, permission_code: str) -> List[BasePolicy]:
        """
        Get all policies for a permission code.
        
        Args:
            permission_code: Permission code to look up
            
        Returns:
            List[BasePolicy]: List of policies (sorted by priority)
        """
        return self._policies.get(permission_code, [])
    
    def evaluate_policies(
        self,
        user,
        permission_code: str,
        obj=None,
        context=None
    ) -> tuple[bool, Optional[str]]:
        """
        Evaluate all policies for a permission code.
        
        All policies must pass (AND logic) for authorization to succeed.
        If any policy returns False, evaluation stops and returns False.
        
        NOTE: If no policies are registered for a permission, this returns
        (True, None) meaning "no policy-based restrictions". Policies are
        constraints, not grants - they can only deny or allow what would
        otherwise be granted by RBAC.
        
        Args:
            user: User requesting permission
            permission_code: Permission code to evaluate
            obj: Object being accessed (optional)
            context: Additional context (optional)
            
        Returns:
            tuple: (allowed: bool, denial_reason: Optional[str])
        """
        policies = self.get_policies(permission_code)
        
        if not policies:
            # No policies registered = no policy-based restrictions
            # This means policies don't deny, but also don't grant
            return True, None
        
        logger.debug(
            f"Evaluating {len(policies)} policies for {permission_code}"
        )
        
        for policy in policies:
            try:
                allowed = policy.allows(user, obj, context)
                
                if not allowed:
                    reason = policy.get_denial_reason(user, obj, context)
                    logger.debug(
                        f"Policy {policy.__class__.__name__} denied: {reason}"
                    )
                    return False, reason
                
            except Exception as e:
                logger.error(
                    f"Policy {policy.__class__.__name__} evaluation failed: {e}",
                    exc_info=True
                )
                raise PolicyEvaluationError(
                    f"Policy evaluation failed for {policy.__class__.__name__}: {e}"
                )
        
        # All policies passed
        return True, None
    
    def unregister(self, policy_class: Type[BasePolicy]) -> None:
        """
        Unregister a policy class.
        
        Args:
            policy_class: Policy class to unregister
        """
        for code, policies in list(self._policies.items()):
            self._policies[code] = [
                p for p in policies if not isinstance(p, policy_class)
            ]
            if not self._policies[code]:
                del self._policies[code]
    
    def clear(self) -> None:
        """Clear all registered policies. Useful for testing."""
        self._policies.clear()
    
    def get_all_policies(self) -> Dict[str, List[BasePolicy]]:
        """
        Get all registered policies.
        
        Returns:
            Dict[str, List[BasePolicy]]: All policies by permission code
        """
        return self._policies.copy()


# Global registry instance
policy_registry = PolicyRegistry()


def register_policy(policy_class: Type[BasePolicy]) -> Type[BasePolicy]:
    """
    Decorator to register a policy class.
    
    Usage:
        @register_policy
        class MyPolicy(BasePolicy):
            permission_code = "my.permission"
            
            def allows(self, user, obj=None, context=None):
                return True
    
    Args:
        policy_class: Policy class to register
        
    Returns:
        The same policy class (for chaining)
    """
    policy_registry.register(policy_class)
    return policy_class


# ============================================================================
# Example Policies (for testing and demonstration)
# ============================================================================


class OwnerOnlyPolicy(BasePolicy):
    """
    Policy that only allows the resource owner to access it.
    
    The object must implement get_owner() method.
    """
    
    permission_code = []  # Must be set when used
    
    def allows(self, user, obj=None, context=None) -> bool:
        if obj is None:
            return False
        
        if not hasattr(obj, 'get_owner'):
            logger.warning(
                f"Object {obj} does not implement get_owner()"
            )
            return False
        
        owner = obj.get_owner()
        return owner == user
    
    def get_denial_reason(self, user, obj=None, context=None) -> str:
        return "Only the resource owner can perform this action"


class AuthenticatedOnlyPolicy(BasePolicy):
    """
    Policy that only allows authenticated users.
    """
    
    permission_code = []  # Must be set when used
    
    def allows(self, user, obj=None, context=None) -> bool:
        return user and user.is_authenticated
    
    def get_denial_reason(self, user, obj=None, context=None) -> str:
        return "Authentication required"


class ActiveUserOnlyPolicy(BasePolicy):
    """
    Policy that only allows active users.
    """
    
    permission_code = []  # Must be set when used
    
    def allows(self, user, obj=None, context=None) -> bool:
        return user and user.is_authenticated and user.is_active
    
    def get_denial_reason(self, user, obj=None, context=None) -> str:
        if not user or not user.is_authenticated:
            return "Authentication required"
        return "Your account is inactive"

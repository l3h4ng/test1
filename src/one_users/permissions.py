__author__ = 'TOANTV'
from rest_framework.permissions import BasePermission

SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')


class IsOneUserAuthenticated(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated()


class IsOneSuperAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_superuser


class IsOneUserAdmin(BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated():
            return request.user.is_smod==1 or request.user.is_superuser
        return False


class IsOneUserScanner(BasePermission):
    def has_permission(self, request, view):
        if request.user and request.user.is_authenticated():
            return request.user.is_smod == 2 or request.user.is_superuser
        return False


# class IsOneSuperAdminOrIsSelf(BasePermission):
#     def has_object_permission(self, request, view, obj):
#         return obj == request.user or request.user.is_superuser

class IsOneUserAuthenticatedReadOnlyOrScanner(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return request.user and request.user.is_authenticated()
        elif request.user and request.user.is_authenticated():
            return request.user.is_smod >= 1 or request.user.is_superuser
        return False


class IsOneUserAuthenticatedReadOnly(BasePermission):
    def has_permission(self, request, view):
        return (
            request.method in SAFE_METHODS and
            request.user and
            request.user.is_authenticated()
        )


class AllowAnyReadOnly(BasePermission):
    def has_permission(self, request, view):
        return (
            request.method in SAFE_METHODS or
            request.user and
            request.user.is_authenticated
        )

class IsOneUserReadOnlyOrSuperAdmin(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return request.user and request.user.is_authenticated()
        else:
            return request.user and request.user.is_superuser


class IsOneUserReadOnlyOrScanner(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return request.user and request.user.is_authenticated()
        else:
            return request.user.is_smod == 2 or request.user.is_superuser

class IsOneUserAuthenticatedReadOnlyOrAdmin(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return request.user and request.user.is_authenticated()
        else:
            return request.user.is_smod == 1 or request.user.is_superuser

class IsAnyOneReadOnly(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True
        else:
            return False
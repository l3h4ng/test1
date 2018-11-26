# -*- coding: utf-8 -*-
import re

from django.db.models import Q
from django.utils.translation import ugettext_lazy as _
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework import status
from rest_framework.renderers import JSONRenderer

from one_auth.authentication import OneTokenAuthentication
from one_users.models import OneUsers
from one_users.permissions import IsOneUserAuthenticated, IsOneUserAdmin
from one_users.serializers import OneUserProfileSerializer, ChangePasswordUserSerializer
from one_users.serializers import OneUserSerializer, OneUserDetailsSerializer, OneUserSerializerEmail
from sbox4web.views import JSONResponse


# Get
class OneUsersList(generics.ListCreateAPIView):
    queryset = OneUsers.objects.filter(~Q(id=2))
    serializer_class = OneUserSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAdmin,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    search_fields = ('username', 'email')
    filter_fields = ('username', 'is_superuser', 'email', 'is_active')


# GET /users/<pk>/
# PUT /users/<pk>/
# DELETE /users/<pk>/
class OneUserDetails(generics.RetrieveUpdateDestroyAPIView):
    queryset = OneUsers.objects.all()
    serializer_class = OneUserDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAdmin,)
    renderer_classes = (JSONRenderer,)

    def get_object(self):
        return OneUsers.objects.get(pk=self.kwargs['pk'])

    def perform_update(self, serializer):
        serializer.save()
        # Update password
        user = self.get_object()
        if "password" in self.request.data and self.request.data["password"] != "":
            password_serializer = ChangePasswordUserSerializer(data={"password": self.request.data["password"]})
            if password_serializer.is_valid(raise_exception=True):
                # Logout all sessions if new password is not current password
                if not user.check_password(self.request.data["password"]):
                    OneTokenAuthentication().delete_another_tokens(user)
                user.set_password(self.request.data["password"])
                user.save()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.is_superuser == 1 and OneUsers.objects.filter(is_superuser=1, is_active=1).count() == 1:
            return JSONResponse({'status': 'error',
                                 "error": _(
                                     "You cannot delete last supper user.\nPlease change super user permission to another user.")},
                                status=status.HTTP_400_BAD_REQUEST)
        instance.is_active = 0
        instance.save()
        return JSONResponse({'status': 'success'}, status=status.HTTP_204_NO_CONTENT)


# GET /me/
# PUT /me/
class OneAuthenticatedUserDetail(generics.RetrieveUpdateAPIView):
    queryset = OneUsers.objects.all()
    serializer_class = OneUserProfileSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_object(self):
        return self.request.user


# POST /users/me/reset_password/
class OneUserSetPassword(generics.CreateAPIView):
    queryset = OneUsers.objects.all()
    serializer_class = ChangePasswordUserSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def create(self, request, *args, **kwargs):
        user = request.user
        request_data = request.data
        if "current-password" in request_data and "new-password" in request_data:
            if user.check_password(request_data["current-password"]):
                password = self.request.data["new-password"]
                if len(password) < 6:
                    return JSONResponse({'status': "error",
                                         'data': {"password": _(
                                             "Ensure passwords are 6 characters or longer,contain at least one uppercase letter, lowercase letter and digit.")}},
                                        status=status.HTTP_400_BAD_REQUEST)
                else:
                    count = 0
                    if re.search(r'[A-Z]', password):
                        count += 1
                    if re.search(r'[a-z]', password):
                        count += 1
                    if re.search(r'[0-9]', password):
                        count += 1
                    if count < 3:
                        return JSONResponse({'status': "error",
                                             'data': {"password": _(
                                                 "Ensure passwords are 6 characters or longer,contain at least one uppercase letter, lowercase letter and digit.")}},
                                            status=status.HTTP_400_BAD_REQUEST)

                if "new-password" in request_data:
                    user.set_password(request_data["new-password"])
                    user.save()
                    # Logout all sessions
                    if request_data["new-password"] != request_data["current-password"]:
                        OneTokenAuthentication().delete_another_tokens(user)
                    return JSONResponse({'status': 'success'}, status=status.HTTP_200_OK)
            else:
                return JSONResponse({'status': "error",
                                     'data': {"password": _(
                                         "The current password is not correct. Please try again!")}},
                                    status=status.HTTP_400_BAD_REQUEST)
        else:
            return JSONResponse({'status': "error",
                                 'data': {"Must include \"current-password\" and \"new-password!\""}},
                                status=status.HTTP_400_BAD_REQUEST)


class OneUsersListEmail(generics.ListCreateAPIView):
    queryset = OneUsers.objects.filter(~Q(id=2), is_active=True)
    serializer_class = OneUserSerializerEmail
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    search_fields = ('username', 'email')
    filter_fields = ('username', 'email')

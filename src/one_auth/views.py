from django.contrib.auth.signals import user_logged_in, user_logged_out
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.parsers import JSONParser
from rest_framework.permissions import AllowAny

from one_auth.authentication import OneTokenAuthentication
from one_auth.models import OneAuthToken
from one_auth.serializers import OneLoginSerializer, OneLogoutSerializers
from one_auth.settings import oneauth_settings
from one_users.permissions import IsOneUserAuthenticated, IsOneSuperAdmin
from sbox4web.views import JSONResponse


class LoginView(GenericAPIView):
    permission_classes = (AllowAny,)
    serializer_class = OneLoginSerializer

    def post(self, request, format=None):
        data = JSONParser().parse(request)
        self.serializer = self.get_serializer(data=data)
        self.serializer.is_valid(raise_exception=True)
        self.user = self.serializer.validated_data['user']
        if self.user:
            token = OneAuthToken.objects.create(self.user)
            user_logged_in.send(sender=request.user.__class__, request=request, user=self.user)
            UserSerializer = oneauth_settings.USER_SERIALIZER
            return JSONResponse(
                {'user': UserSerializer(self.user, context=self.get_serializer_context()).data, 'one-token': token},
                status=status.HTTP_200_OK)


class LogoutView(GenericAPIView):
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    serializer_class = OneLogoutSerializers

    def post(self, request, format=None):
        request._auth.delete()
        user_logged_out.send(sender=request.user.__class__, request=request, user=request.user)
        return JSONResponse({"status": "sucess"}, status=status.HTTP_200_OK)


class LogoutAllView(GenericAPIView):
    '''
    Log the user out of all sessions
    I.E. deletes all auth tokens for the user
    '''
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneSuperAdmin,)

    def post(self, request, format=None):
        request.user.auth_token_set.all().delete()
        user_logged_out.send(sender=request.user.__class__, request=request, user=request.user)
        return JSONResponse({"status": "sucess"}, status=status.HTTP_200_OK)

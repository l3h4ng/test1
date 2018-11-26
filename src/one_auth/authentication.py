# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
from django.conf import settings
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from rest_framework import exceptions
from rest_framework.authentication import (
    BaseAuthentication
)

from one_auth.crypto import hash_token
from one_auth.models import OneAuthToken
from one_auth.settings import CONSTANTS

User = settings.AUTH_USER_MODEL


class OneTokenAuthentication(BaseAuthentication):
    '''
    This authentication scheme uses Knox AuthTokens for authentication.

    Similar to DRF's TokenAuthentication, it overrides a large amount of that
    authentication scheme to cope with the fact that Tokens are not stored
    in plaintext in the database

    If succesful
    - `request.user` will be a django `User` instance
    - `request.auth` will be an `AuthToken` instance
    '''
    model = OneAuthToken

    def authenticate(self, request):
        auth = request.META.get('HTTP_ONE_TOKEN', '')
        if not auth:
            return None
        if auth.find(' ') != -1:
            msg = _('Invalid token header. '
                    'Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        user, auth_token = self.authenticate_credentials(auth)
        return (user, auth_token)

    def authenticate_credentials(self, token):
        '''
        Due to the random nature of hashing a salted value, this must inspect
        each auth_token individually to find the correct one.

        Tokens that have expired will be deleted and skipped
        '''
        msg = _('Invalid token.')
        for auth_token in OneAuthToken.objects.filter(
                token_key=token[:CONSTANTS.TOKEN_KEY_LENGTH]):
            for other_token in auth_token.user.auth_token_set.all():
                if other_token.digest != auth_token.digest and other_token.expires is not None:
                    if other_token.expires < timezone.now():
                        other_token.delete()
            if auth_token.expires is not None:
                if auth_token.expires < timezone.now():
                    auth_token.delete()
                    continue
            try:
                digest = hash_token(token, auth_token.salt)
            except TypeError:
                raise exceptions.AuthenticationFailed(msg)
            if digest == auth_token.digest:
                return self.validate_user(auth_token)
        # Authentication with this token has failed
        raise exceptions.AuthenticationFailed(msg)

    def validate_user(self, auth_token):
        if not auth_token.user.is_active:
            raise exceptions.AuthenticationFailed(
                _('User inactive or deleted.'))
        return (auth_token.user, auth_token)

    def authenticate_header(self, request):
        return 'one-token'

    def delete_another_tokens(self, user):
        one_auth_tokens = OneAuthToken.objects.select_related('user').filter(user=user)
        for auth_tokens in one_auth_tokens:
            auth_tokens.delete()

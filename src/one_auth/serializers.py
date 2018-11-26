# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
from django.contrib.auth import authenticate
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers, exceptions


class OneLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(style={'input_type': 'password'})

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = None
        if email and password:
            user = authenticate(email=email, password=password)
            if user:
                if not user.is_active:
                    msg = _('User account is disabled.')
                    # raise exceptions.ValidationError(msg)
                    raise serializers.ValidationError(msg)
            else:
                msg = _('Unable to login with provided credentials.')
                # raise exceptions.ValidationError(msg)
                raise serializers.ValidationError(msg)

        else:
            msg = _('Must include "email" and "password".')
            raise exceptions.ValidationError(msg)

        attrs['user'] = user
        return attrs


class OneLogoutSerializers(serializers.Serializer):
    pass

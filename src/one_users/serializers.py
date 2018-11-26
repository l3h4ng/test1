# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
import re

from rest_framework import serializers

from one_users.models import OneUsers


# Class for admin gets, create user
class OneUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = OneUsers
        fields = (
            'id', 'username', 'password', 'email', 'fullname', 'is_smod', 'is_active', 'date_joined', "last_login")
        read_only_fields = ('date_joined', 'last_login', 'id')
        extra_kwargs = {'password': {'write_only': True}}

    def validate_password(self, password):
        if len(password) < 6:
            raise serializers.ValidationError(
                "Ensure passwords are 6 characters or longer,contain at least one uppercase letter, lowercase letter and digit.")
        else:
            count = 0
            if re.search(r'[A-Z]', password):
                count += 1
            if re.search(r'[a-z]', password):
                count += 1
            if re.search(r'[0-9]', password):
                count += 1
            if count < 3:
                raise serializers.ValidationError(
                    "Ensure passwords are 6 characters or longer,contain at least one uppercase letter, lowercase letter and digit.")
        return password

    def create(self, validated_data):
        user = OneUsers(
            **validated_data
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


# Class for admin get, update and delete user information
# /users/
class OneUserDetailsSerializer(serializers.ModelSerializer):
    class Meta:
        model = OneUsers
        fields = (
            'id', 'username', 'email', 'fullname', 'is_smod', 'is_active', 'date_joined', "last_login")
        read_only_fields = ('date_joined', 'last_login', 'email', 'id')
        extra_kwargs = {'password': {'write_only': True}}


# Serializer for authenticated user
# /me/
class OneUserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = OneUsers
        fields = ('id', 'username', 'email', 'fullname', 'is_smod', 'date_joined', 'last_login')
        read_only_fields = ('date_joined', 'last_login', 'email', 'id')


# Serializer for set password
class ChangePasswordUserSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=128, allow_null=False)

    class Meta:
        fields = ('password',)
        extra_kwargs = {'password': {'write_only': True}}

    def validate_password(self, password):
        # password = self.get('password')
        if len(password) < 6:
            raise serializers.ValidationError(
                "Ensure passwords are 6 characters or longer,contain at least one uppercase letter, lowercase letter and digit.")
        else:
            count = 0
            if re.search(r'[A-Z]', password):
                count += 1
            if re.search(r'[a-z]', password):
                count += 1
            if re.search(r'[0-9]', password):
                count += 1
            if count < 3:
                raise serializers.ValidationError(
                    "Ensure passwords are 6 characters or longer,contain at least one uppercase letter, lowercase letter and digit.")
        return password


class OneUserSerializerEmail(serializers.ModelSerializer):
    class Meta:
        model = OneUsers
        fields = ('id', 'fullname', 'email')

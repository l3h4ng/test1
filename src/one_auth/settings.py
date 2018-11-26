__author__ = 'TOANTV'
from datetime import timedelta
from django.conf import settings
from django.test.signals import setting_changed
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, 'ONE_AUTH', None)

DEFAULTS = {
    'SECURE_HASH_ALGORITHM': 'cryptography.hazmat.primitives.hashes.SHA512',
    'AUTH_TOKEN_CHARACTER_LENGTH': 64,
    'TOKEN_TTL': timedelta(hours=10),
    'USER_SERIALIZER': 'one_users.serializers.OneUserDetailsSerializer',
}


IMPORT_STRINGS = {
    'SECURE_HASH_ALGORITHM',
    'USER_SERIALIZER',
}

oneauth_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)

def reload_api_settings(*args, **kwargs):
    global knox_settings
    setting, value = kwargs['setting'], kwargs['value']
    if setting == 'ONE_AUTH':
        knox_settings = APISettings(value, DEFAULTS, IMPORT_STRINGS)

setting_changed.connect(reload_api_settings)

class CONSTANTS:
    '''
    Constants cannot be changed at runtime
    '''
    TOKEN_KEY_LENGTH = 8
    DIGEST_LENGTH = 128
    SALT_LENGTH = 16

    def __setattr__(self, *args, **kwargs):
        raise RuntimeError('''
            Constant values must NEVER be changed at runtime, as they are
            integral to the structure of database tables
            ''')
CONSTANTS = CONSTANTS()

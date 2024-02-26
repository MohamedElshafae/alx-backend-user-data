#!/usr/bin/env python3
"""
BasicAuth class
"""
from api.v1.auth.auth import Auth
import base64
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """BasicAuth class"""

    def extract_base64_authorization_header(self, authorization_header: str) \
            -> str:
        """
            Returns the Base64 part of the
            Authorization header for a Basic Authentication
        """
        if not authorization_header \
                or not isinstance(authorization_header, str) \
                or not authorization_header.startswith('Basic '):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self, base64_authorization_header:
                                           str) -> str:
        """
            returns the decoded value of a base64 string
        """
        if not base64_authorization_header \
                or not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header:
                                 str) -> (str, str):
        """
            returns the user email and password from the Base64 decoded value.
        """
        if not decoded_base64_authorization_header \
                or not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        header = decoded_base64_authorization_header.split(':')
        tup = (header[0], header[1])
        return tup

    def user_object_from_credentials(self, user_email: str, user_pwd: str) \
            -> TypeVar('User'):
        """
            returns the User instance based on his email and password.
        """
        if not user_email or not isinstance(user_email, str):
            return None
        elif not user_pwd or not isinstance(user_pwd, str):
            return None
        users = User.search({'email': user_email})
        if users is None or len(users) == 0:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """retrieves the User instance for a request"""
        if request is None:
            return None
        auth_header = self.authorization_header(request)
        auth_header = self.extract_base64_authorization_header(auth_header)
        decoded_auth_header = self.decode_base64_authorization_header(
            auth_header)
        user_email, user_pwd = self.extract_user_credentials(
            decoded_auth_header)
        return self.user_object_from_credentials(user_email, user_pwd)

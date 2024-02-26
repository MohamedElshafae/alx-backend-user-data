#!/usr/bin/env python3
"""
Auth class
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Auth class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Require authentication"""
        if path and path[-1] != '/':
            path += '/'
        if excluded_paths is None or path not in excluded_paths or not path:
            return True
        return False

    def authorization_header(self, request=None) -> str:
        """document"""
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """document"""
        return None

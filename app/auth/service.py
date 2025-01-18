"""
Authentication Service Module

This module provides a comprehensive authentication service using MongoDB and JWT tokens.
It handles user authentication, token management, and security features like account lockout.

Dependencies:
    - Flask
    - PyJWT
    - Argon2
    - PyMongo
    - Python 3.8+

Author: Ayman Errarhiche
Version: 1.0.0
"""

from flask import g, request, jsonify
from datetime import datetime
import jwt
from functools import wraps
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from contextlib import contextmanager
import logging

from app.config import Config
from ..db.mongo_handler import MongoHandler

logger = logging.getLogger(__name__)

class AuthService:
    """
    Authentication service that manages user authentication and token handling.

    This class provides methods for user login, token generation, validation,
    and management of authentication states including account lockout.

    Attributes:
        ph (PasswordHasher): Argon2 password hasher instance
        secret_key (str): Secret key for JWT token generation
        jwt_expires (timedelta): Token expiration duration
        max_login_attempts (int): Maximum allowed login attempts before lockout
        lockout_duration (timedelta): Duration of account lockout
        database_name (str): Name of the MongoDB database
    """
    
    def __init__(self):
        """Initialize the AuthService with configuration settings."""
        self.ph = PasswordHasher()
        self.secret_key = Config.SECRET_KEY
        self.jwt_expires = Config.JWT_EXPIRES
        self.max_login_attempts = Config.MAX_LOGIN_ATTEMPTS
        self.lockout_duration = Config.LOCKOUT_DURATION
        self.database_name = 'mongoauth'

    @contextmanager
    def _get_db(self):
        """
        Context manager for database connections.

        Yields:
            MongoHandler: Connected database handler instance.

        Ensures proper connection handling and cleanup.
        """
        db = None
        try:
            db = MongoHandler()
            db.connect(self.database_name)
            yield db
        finally:
            if db:
                db.close()

    def generate_token(self, user_id: str):
        """
        Generate a new JWT token for a user.

        Args:
            user_id (str): The unique identifier of the user.

        Returns:
            tuple: (str, datetime) Token string and its expiration datetime.
        """
        expires_at = datetime.utcnow() + self.jwt_expires
        token = jwt.encode({'user_id': user_id, 'exp': expires_at.timestamp()}, self.secret_key, algorithm="HS256")
        return token, expires_at

    def refresh_token(self):
        """
        Refresh an existing valid token.

        Returns:
            tuple: (dict, int) JSON response and HTTP status code.

        The method validates the existing token and generates a new one
        if the current token is valid but close to expiration.
        """
        with self._get_db() as db:
            try:
                token = request.headers.get('Authorization', '').split(" ")[1]
                if not token:
                    return jsonify({'message': 'Token is missing'}), 401

                data = jwt.decode(token, self.secret_key, algorithms=["HS256"], options={"verify_exp": False})
                user_id = data.get('user_id')
                if not user_id:
                    return jsonify({'message': 'Invalid token'}), 401

                existing_token = db.find_one('auth_tokens', {
                    'token': token,
                    'is_revoked': False
                })

                if not existing_token:
                    return jsonify({'message': 'Invalid or revoked token'}), 401

                new_token, expires_at = self.generate_token(user_id)
                db.insert_one('auth_tokens', {
                    'user_id': user_id,
                    'token': new_token,
                    'expires_at': expires_at,
                    'is_revoked': False
                })
                return jsonify({'token': new_token}), 200

            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token has expired, please login again'}), 401
            except Exception as e:
                logger.error(f"Token refresh error: {e}")
                return jsonify({'message': 'Token refresh failed'}), 500

    def validate_token(self):
        """
        Validate a token's authenticity and expiration.

        Returns:
            tuple: (dict, int) JSON response and HTTP status code.

        Checks if the token is valid, not expired, and corresponds to a real user.
        """
        try:
            token = request.headers.get('Authorization', '').split(" ")[1]
            if not token:
                return jsonify({'message': 'Token is missing'}), 401

            data = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return jsonify({'user_id': data['user_id']}), 200
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

    def token_required(self, f):
        """
        Decorator to protect routes that require valid authentication.

        Args:
            f (function): The route function to be protected.

        Returns:
            function: Decorated function that checks for valid token before proceeding.
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            with self._get_db() as db:
                try:
                    token = None
                    if 'Authorization' in request.headers:
                        token = request.headers['Authorization'].split(" ")[1]

                    if not token:
                        return jsonify({'message': 'Token is missing'}), 401

                    # Find valid token
                    token_data = db.find_one('auth_tokens', {
                        'token': token,
                        'expires_at': {'$gt': datetime.utcnow()},
                        'is_revoked': False
                    })

                    if not token_data:
                        return jsonify({'message': 'Invalid or expired token'}), 401

                    data = jwt.decode(token, self.secret_key, algorithms=["HS256"])
                    current_user_id = data['user_id']

                    if current_user_id != token_data['user_id']:
                        return jsonify({'message': 'Token validation failed'}), 401

                    g.current_user_id = current_user_id
                    return f(*args, **kwargs)

                except jwt.ExpiredSignatureError:
                    return jsonify({'message': 'Token has expired'}), 401
                except Exception as e:
                    logger.error(f"Token validation error: {str(e)}")
                    return jsonify({'message': 'Token validation failed'}), 401

        return decorated

    def _cleanup_user_tokens(self, db: MongoHandler, user_id: str):
        """
        Clean up user's tokens by revoking old ones and removing expired ones.

        Args:
            db (MongoHandler): Database connection handler.
            user_id (str): User ID whose tokens need cleanup.

        Raises:
            Exception: If token cleanup fails.
        """
        try:
            # Revoke all existing tokens
            db.db['auth_tokens'].update_many(
                {'user_id': user_id, 'is_revoked': False},
                {'$set': {'is_revoked': True}}
            )
            
            # Delete revoked and expired tokens
            db.db['auth_tokens'].delete_many({
                'user_id': user_id,
                '$or': [
                    {'is_revoked': True},
                    {'expires_at': {'$lt': datetime.utcnow()}}
                ]
            })
            
            logger.info(f"Completed token cleanup for user {user_id}")
        except Exception as e:
            logger.error(f"Error during token cleanup: {e}")
            raise

    def login(self, identifier: str, password: str):
        """
        Authenticate a user using email, phone number, or username.

        Args:
            identifier (str): User's email, phone number, or username.
            password (str): User's password.

        Returns:
            tuple: (dict, int) JSON response with user data and token if successful,
                  or error message and appropriate HTTP status code.

        The method handles:
            - Multiple identifier types (email/phone/username)
            - Password verification
            - Account lockout after failed attempts
            - Token generation and user session management
        """
        with self._get_db() as db:
            try:
                if not identifier or not password:
                    return jsonify({'message': 'Identifier and password are required'}), 400

                user = db.find_one('users', {
                    '$or': [
                        {'email': identifier},
                        {'phone_number': identifier},
                        {'username': identifier}
                    ]
                })

                if not user:
                    return jsonify({'message': 'Invalid credentials'}), 401

                if user.get('locked_until') and user['locked_until'] > datetime.utcnow():
                    return jsonify({
                        'message': 'Account is locked. Please try again later.',
                        'locked_until': user['locked_until'].isoformat()
                    }), 401

                try:
                    stored_hash = user['password']
                    salt = user['password_salt']
                    self.ph.verify(stored_hash, f"{password}{salt}")

                    self._cleanup_user_tokens(db, str(user['_id']))

                    db.db['users'].update_one(
                        {'_id': user['_id']},
                        {
                            '$set': {
                                'login_attempts': 0,
                                'locked_until': None,
                                'last_login': datetime.utcnow()
                            }
                        }
                    )

                    token, expires_at = self.generate_token(str(user['_id']))

                    db.insert_one('auth_tokens', {
                        'user_id': str(user['_id']),
                        'token': token,
                        'expires_at': expires_at,
                        'is_revoked': False
                    })

                    return jsonify({
                        'token': token,
                        'user': {
                            'id': str(user['_id']),
                            'username': user['username'],
                            'email': user['email'],
                            'email_verification_status': user.get('email_verification_status', 'unverified'),
                            'phone_number': user.get('phone_number'),
                            'phone_verification_status': user.get('phone_verification_status', 'unverified'),
                            'first_name': user.get('first_name'),
                            'last_name': user.get('last_name'),
                            'date_of_birth': user.get('date_of_birth')
                        }
                    }), 200

                except VerifyMismatchError:
                    new_attempts = user.get('login_attempts', 0) + 1
                    locked_until = None

                    if new_attempts >= self.max_login_attempts:
                        locked_until = datetime.utcnow() + self.lockout_duration

                    db.db['users'].update_one(
                        {'_id': user['_id']},
                        {
                            '$set': {
                                'login_attempts': new_attempts,
                                'locked_until': locked_until
                            }
                        }
                    )

                    return jsonify({'message': 'Invalid credentials'}), 401

            except Exception as e:
                logger.error(f"Login error: {str(e)}")
                return jsonify({'message': 'Login failed', 'error': str(e)}), 500

    def logout(self, token: str):
        """
        Log out a user by revoking their current token.

        Args:
            token (str): The token to be revoked.

        Returns:
            tuple: (dict, int) JSON response and HTTP status code.

        Marks the token as revoked in the database, preventing its future use.
        """
        with self._get_db() as db:
            try:
                db.db['auth_tokens'].update_one(
                    {'token': token},
                    {'$set': {'is_revoked': True}}
                )
                return jsonify({'message': 'Successfully logged out'}), 200
            except Exception as e:
                logger.error(f"Logout error: {str(e)}")
                return jsonify({'message': 'Logout failed'}), 500
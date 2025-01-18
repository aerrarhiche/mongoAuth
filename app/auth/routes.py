from datetime import datetime
import secrets
from venv import logger
from argon2 import PasswordHasher
from flask import Blueprint, request, jsonify

from app.db.mongo_handler import MongoHandler
from .service import AuthService

auth_bp = Blueprint('auth', __name__)
auth_service = AuthService()

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    return auth_service.login(data.get('username'), data.get('password'))

@auth_bp.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization', '').split(" ")[1]
    return auth_service.logout(token)

@auth_bp.route('/refresh-token', methods=['POST'])
def refresh_token():
    return auth_service.refresh_token()

@auth_bp.route('/validate-token', methods=['POST'])
def validate_token():
    return auth_service.validate_token()

@auth_bp.route('/register', methods=['POST'])
def register():
    db = MongoHandler()
    try:
        db.connect('mongoauth')
        data = request.get_json()
        
        # Required fields
        required_fields = ['username', 'password', 'email']
        if not all(field in data for field in required_fields):
            return jsonify({'message': 'Missing required fields'}), 400

        # Check if user exists
        existing_user = db.find_one('users', {
            '$or': [
                {'username': data['username']},
                {'email': data['email']},
                {'phone_number': data.get('phone_number')} if data.get('phone_number') else None
            ]
        })
        
        if existing_user:
            return jsonify({'message': 'Username, email, or phone number already exists'}), 400

        # Create new user
        salt = secrets.token_hex(16)
        ph = PasswordHasher()
        password_hash = ph.hash(f"{data['password']}{salt}")

        user_data = {
            'username': data['username'],
            'email': data['email'],
            'email_verification_status': 'unverified',
            'phone_number': data.get('phone_number'),
            'phone_verification_status': 'unverified' if data.get('phone_number') else None,
            'date_of_birth': datetime.strptime(data['date_of_birth'], '%Y-%m-%d') if data.get('date_of_birth') else None,
            'password': password_hash,
            'password_salt': salt,
            'first_name': data.get('first_name', ''),
            'last_name': data.get('last_name', ''),
            'created_at': datetime.utcnow(),
            'login_attempts': 0,
            'locked_until': None,
            'last_login': None
        }

        user_id = db.insert_one('users', user_data)
        
        return jsonify({
            'message': 'User registered successfully',
            'user_id': str(user_id)
        }), 201

    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 500
    finally:
        db.close()
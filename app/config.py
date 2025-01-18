import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key')
    JWT_EXPIRES = timedelta(hours=24)
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)
    
    # MongoDB settings
    MONGODB_URI = os.getenv('MONGODB_URI')
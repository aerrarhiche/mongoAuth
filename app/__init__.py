from flask import Flask
from .config import Config
from .auth.routes import auth_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')

    return app
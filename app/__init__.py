from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_talisman import Talisman
from flask_csp.csp import csp_header
from config import Config
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    csrf.init_app(app)
    
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)

    
    
    # Security headers
    # Talisman(
    #     app,
    #     force_https=False,
    #     strict_transport_security=True,
    #     session_cookie_secure=True,
    #     content_security_policy=app.config['CSP'],
    #     content_security_policy_nonce_in=['script-src']
    # )
    
    # Register blueprints
    from .auth.routes import auth_bp
    from .chat.routes import chat_bp

    app.register_blueprint(auth_bp)

    app.register_blueprint(chat_bp)

    # Create database tables
    with app.app_context():
        db.create_all()
    
    
    return app

from app import models
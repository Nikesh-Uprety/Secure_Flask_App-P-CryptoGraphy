import os
from datetime import timedelta


class Config:
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")  # Fallback for development
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///secure_chat.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File Uploads
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png','jpg', 'jpeg', 'gif', 'doc', 'docx'}

    # Cryptography
    RSA_KEY_SIZE = 2048
    SIGNATURE_ALGORITHM = 'SHA256'
    ENCRYPTION_ALGORITHM = 'AES256-CBC'

    # Security Headers
    CSP = {
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
        'style-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "fonts.googleapis.com"],
        'font-src': ["'self'", "fonts.gstatic.com"],
        'img-src': ["'self'", "data:"],
        'connect-src': ["'self'"],
        'object-src': "'none'",
        'base-uri': "'self'",
        'frame-ancestors': "'none'"
    }

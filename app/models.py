from datetime import datetime, timezone
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy='dynamic')
    
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        # Generate RSA key pair for each user
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        self.private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        self.public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_private_key(self):
        return serialization.load_pem_private_key(
            self.private_key.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
    
    def get_public_key(self):
        return serialization.load_pem_public_key(
            self.public_key.encode('utf-8'),
            backend=default_backend()
        )
    
    def __repr__(self):
        return f'<User {self.username}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    encrypted_body = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    is_file = db.Column(db.Boolean, default=False)
    file_path = db.Column(db.String(256))
    file_signature = db.Column(db.Text)

    def local_timestamp(self):
        """Returns timestamp converted to local time"""
        return self.timestamp.replace(tzinfo=timezone.utc).astimezone(tz=None)
    @property
    def formatted_timestamp(self):
        return self.timestamp.strftime('%Y-%m-%d %H:%M')
    @property
    def js_timestamp(self):
        """Returns ISO format for JavaScript"""
        return self.timestamp.replace(tzinfo=timezone.utc).isoformat()

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))
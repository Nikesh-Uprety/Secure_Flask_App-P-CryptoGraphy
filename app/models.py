from datetime import datetime, timezone
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64
from sqlalchemy import or_, and_


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True,
                         unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now())
    last_seen = db.Column(
        db.DateTime, default=lambda: datetime.now())

    # Relationships
    messages_sent = db.relationship('Message',
                                    foreign_keys='Message.sender_id',
                                    backref='sender',
                                    lazy='dynamic')
    messages_received = db.relationship('Message',
                                        foreign_keys='Message.recipient_id',
                                        backref='recipient',
                                        lazy='dynamic')
    sent_requests = db.relationship('ChatRequest',
                                    foreign_keys='ChatRequest.sender_id',
                                    backref='sender',
                                    lazy='dynamic')
    received_requests = db.relationship('ChatRequest',
                                        foreign_keys='ChatRequest.recipient_id',
                                        backref='recipient',
                                        lazy='dynamic')

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        # Generate RSA key pair for each new user
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

    def has_pending_request_to(self, other_user_id):
        """Check if current user has pending request to another user"""
        return ChatRequest.query.filter_by(
            sender_id=self.id,
            recipient_id=other_user_id,
            status='pending'
        ).first() is not None

    def has_pending_request_from(self, other_user_id):
        """Check if current user has pending request from another user"""
        return ChatRequest.query.filter_by(
            sender_id=other_user_id,
            recipient_id=self.id,
            status='pending'
        ).first() is not None

    def has_active_chat_with(self, other_user_id):
        """Check if active chat exists between users"""
        return ChatRequest.query.filter(
            or_(
                and_(
                    ChatRequest.sender_id == self.id,
                    ChatRequest.recipient_id == other_user_id,
                    ChatRequest.status == 'accepted'
                ),
                and_(
                    ChatRequest.sender_id == other_user_id,
                    ChatRequest.recipient_id == self.id,
                    ChatRequest.status == 'accepted'
                )
            )
        ).first() is not None

    def get_chat_status_with(self, other_user_id):
        """
        Get the chat relationship status between current user and another user
        Returns: 'active', 'pending', 'requested', or 'available'
        """
        if self.has_active_chat_with(other_user_id):
            return 'active'
        if self.has_pending_request_to(other_user_id):
            return 'pending'
        if self.has_pending_request_from(other_user_id):
            return 'requested'
        return 'available'

    def get_public_key_fingerprint(self):
        """Get shortened fingerprint of public key for display"""
        import hashlib
        key_hash = hashlib.sha256(self.public_key.encode('utf-8')).hexdigest()
        return f"{key_hash[:6]}...{key_hash[-6:]}"

    def __repr__(self):
        return f'<User {self.username}>'


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    encrypted_body = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, index=True,
                          default=lambda: datetime.now())
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


class ChatRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    # pending, accepted, rejected
    status = db.Column(db.String(20), nullable=False, default='pending')

    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    updated_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Exact ISO8601 string used for signing and verifying — prevents microsecond mismatches
    created_at_str = db.Column(db.String(40), nullable=False)

    # Digital signature of the request
    signature = db.Column(db.Text, nullable=True)

    def formatted_created_at(self):
        return self.created_at.strftime('%Y-%m-%d %H:%M')

    def formatted_updated_at(self):
        return self.updated_at.strftime('%Y-%m-%d %H:%M')

    def __repr__(self):
        return f'<ChatRequest {self.sender_id} to {self.recipient_id} - {self.status}>'


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

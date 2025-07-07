from flask import Blueprint

# Create the chat blueprint
chat_bp = Blueprint('chat', __name__)

# Import routes after creating the blueprint to avoid circular imports
from app.chat import routes
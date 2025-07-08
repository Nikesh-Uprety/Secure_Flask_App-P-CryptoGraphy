from app.main import routes  # to avoid circular import
from flask import Blueprint

main_bp = Blueprint('main', __name__)

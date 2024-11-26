from flask import Blueprint

auth_blueprint = Blueprint('auth_bp', __name__, template_folder="templates/auth")

from . import views
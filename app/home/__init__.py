from flask import Blueprint

home_blueprint = Blueprint('home_bp', __name__, template_folder="templates/home", static_folder="static/home")

from . import views
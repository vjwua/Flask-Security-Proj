from flask import Blueprint

account_blueprint = Blueprint('account_bp', __name__, template_folder="templates/account")

from . import views
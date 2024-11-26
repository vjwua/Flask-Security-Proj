from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_simple_captcha import CAPTCHA
from flask_mail import Mail

captcha_config = {
    'SECRET_CAPTCHA_KEY': 'almondcrabapolloncybordterminator',
    'CAPTCHA_LENGTH': 7,
    'CAPTCHA_DIGITS': False,
    'EXPIRE_SECONDS': 600,
    'CAPTCHA_IMG_FORMAT': 'JPEG'
}

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
captcha = CAPTCHA(config=captcha_config)
mail = Mail()

login_manager = LoginManager()
login_manager.login_view = 'auth_bp.login'
login_manager.login_message_category = 'warning'
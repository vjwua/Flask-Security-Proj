from flask import Flask
from .extensions import db, migrate, bcrypt, login_manager, captcha, mail
from config import config

app = Flask(__name__)

def create_app(config_name = 'default'):
    app = Flask(__name__)
    app.config.from_object(config.get(config_name))

    db.init_app(app)
    migrate.init_app(app, db, render_as_batch=True)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    captcha.init_app(app)
    mail.init_app(app)

    with app.app_context():
        from .home import home_blueprint
        app.register_blueprint(home_blueprint, url_prefix='/')

        from .auth import auth_blueprint
        app.register_blueprint(auth_blueprint, url_prefix='/auth')

        from .account import account_blueprint
        app.register_blueprint(account_blueprint, url_prefix='/account')

        return app
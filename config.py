import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    DEBUG = False
    DEVELOPMENT = False
    SECRET_KEY = b"277764450344399279392461713642952840400"
    SECURITY_PASSWORD_SALT = b"56974938695195349851485865927269750324"
    #using secrets.SystemRandom().getrandbits(128)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    #Mail Settings
    MAIL_DEFAULT_SENDER = "noreply@flask.com"
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_DEBUG = False
    MAIL_USERNAME = os.getenv("EMAIL_USER")
    MAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

class DevConfig(Config):
    DEVELOPMENT = True
    DEBUG = True
    WTF_CSRF_ENABLED = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///flask_dev_db.db")

class ProdConfig(Config):
    WTF_CSRF_ENABLED = True
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///flask_prod_db.db")

config = {
    'dev': DevConfig,
    'prod': ProdConfig,
    'default': DevConfig,
}
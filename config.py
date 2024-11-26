import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    DEBUG = False
    DEVELOPMENT = False
    SECRET_KEY = b"277764450344399279392461713642952840400"
    SECURITY_PASSWORD_SALT = b"56974938695195349851485865927269750324"
    #using secrets.SystemRandom().getrandbits(128)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    OAUTH2_PROVIDERS = {
    # Google OAuth 2.0 documentation:
    # https://developers.google.com/identity/protocols/oauth2/web-server#httprest
        'google': {
            'client_id': os.environ.get('GOOGLE_CLIENT_ID'),
            'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET'),
            'authorize_url': 'https://accounts.google.com/o/oauth2/auth',
            'token_url': 'https://accounts.google.com/o/oauth2/token',
            'userinfo': {
                'url': 'https://www.googleapis.com/oauth2/v3/userinfo',
                'email': lambda json: json['email'],
            },
            'scopes': ['https://www.googleapis.com/auth/userinfo.email'],
        },
    }

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
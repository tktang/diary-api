import logging
import os
from logging.handlers import SMTPHandler, RotatingFileHandler

from flask import current_app

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ERROR_MESSAGE_KEY = "message"
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ["access", "refresh"]
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", 14400))
    UPLOAD_FOLDER = os.path.join(basedir, "upload")
    ALLOWED_EXTENSIONS = set(["png", "jpg", "jpeg", "gif", "svg", "bmp"])
    ALLOWED_MIMETYPES_EXTENSIONS = set(
        ["image/apng", "image/bmp", "image/jpeg", "image/png", "image/svg+xml"]
    )
    MAX_CONTENT_LENGTH = 4 * 1024 * 1024

    # mail setup
    MAIL_SERVER = os.environ.get("MAIL_SERVER")
    # MAIL_PORT = int(os.environ.get("MAIL_PORT"))v v
    MAIL_PORT = 587
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS")
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER")
    SECURITY_PASSWORD_SALT = os.environ.get("SECURITY_PASSWORD_SALT")

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DEV_DATABASE_URL"
    ) or "sqlite:///" + os.path.join(basedir, "dev.sqlite")


class TestingConfig(Config):
    TESTING = True
    # Disable CSRF protection in the testing configuration
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("TEST_DATABASE_URL")


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL"
    ) or "sqlite:///" + os.path.join(basedir, "prod.sqlite")

    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        # email errors to the administrators

        credentials = (
            current_app.config["MAIL_USERNAME"],
            current_app.config["MAIL_PASSWORD"],
        )
        mailhost = (current_app.config["MAIL_SERVER"], current_app.config["MAIL_PORT"])
        secure = current_app.config["MAIL_USE_TLS"]
        fromaddr = current_app.config["MAIL_DEFAULT_SENDER"]
        ADMINS = ["oluchiexample@com"]
        subject = "Your Application Failed"

        mail_handler = SMTPHandler(
            mailhost=mailhost,
            fromaddr=fromaddr,
            toaddrs=ADMINS,
            subject=subject,
            credentials=credentials,
            secure=secure,
        )
        mail_handler.setLevel(logging.ERROR)
        mail_handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
        )
        app.logger.addHandler(mail_handler)


        #log to a file
        if not os.path.exists('logs'):
            os.mkdir('logs')
        #limit the log file size to 102MB
        file_handler = RotatingFileHandler('logs/diary_app.log', maxBytes=102400,
                                        backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)

        app.logger.setLevel(logging.INFO)
        app.logger.info('Starting our diary API')



env_config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}

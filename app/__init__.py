import os
import datetime
from flask import Flask, session, render_template, request
from flask_sqlalchemy import SQLAlchemy
# from flask_wtf.csrf import CSRFProtect
from flask_crontab import Crontab
from flask_httpauth import HTTPBasicAuth


db = SQLAlchemy()
# csrf = CSRFProtect()
crontab = Crontab()


auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    global httpauth_user
    global httpauth_hash
    if username == httpauth_user and httpauth_hash == hashlib.sha256(password.encode()).hexdigest():
        return username


def create_app(config_class=None, auth_user=None, auth_hash=None):
    # Make sure the instance path is within the ./data folder.
    data_instance_path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'data', 'instance'))

    app = Flask(__name__, instance_path=data_instance_path, instance_relative_config=True)

    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # First we load everything we need in order to end up with a working app.
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'default.sqlite3')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'ThisIsNotTheKeyYouAreLookingFor'
    app.config['SESSION_COOKIE_HTTPONLY'] = True

    # And now we override any custom settings from config.cfg if it exists.
    app.config.from_pyfile('config.py', silent=True)

    # If we have passed any object on app creation (ie testing), override here.
    if config_class is not None:
        app.config.from_object(config_class)

    db.init_app(app)
    # csrf.init_app(app)
    crontab.init_app(app)

    from app.controllers.api import bp as api_bp
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    # csrf.exempt(api_bp)


    global httpauth_user
    global httpauth_hash
    httpauth_user = auth_user
    httpauth_hash = auth_hash


    # from app.lib.base.provider import Provider

    # This is to be able to access settings from any template (shared variables).
    # @app.context_processor
    # def processor():
    #     def setting_get(name, default=None):
    #         provider = Provider()
    #         return provider.settings().get(name, default)

    #     def user_setting_get(user_id, name, default=None):
    #         provider = Provider()
    #         return provider.user_settings().get(user_id, name, default)

    #     def basename(path):
    #         return os.path.basename(path)

    #     return dict(setting_get=setting_get, user_setting_get=user_setting_get, template=template, basename=basename)

    # @crontab.job(minute="*/5")
    # def cron():
    #     provider = Provider()
    #     cron = provider.cron()
    #     cron.run()

    return app


# This has to be at the bottom.
from app.lib.models import config, sessions, hashcat

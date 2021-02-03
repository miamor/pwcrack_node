import os
import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

data_instance_path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'data', 'instance'))
app = Flask(__name__, instance_path=data_instance_path, instance_relative_config=True)
try:
    os.makedirs(app.instance_path)
except OSError:
    pass
app.config.from_pyfile('config.py', silent=True)

db.init_app(app)
# database = SqliteDatabase(os.path.dirname(os.path.abspath( __file__ )) + os.sep + "hashcatnode.db")

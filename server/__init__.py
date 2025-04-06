# server/__init__.py
from flask import Flask
from .config import Config  # Note the relative import
from .extensions import db, bcrypt, migrate

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)
    
    return app
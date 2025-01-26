from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    _password_hash = db.Column(db.String(128), nullable=False)

    
    recipes = db.relationship('Recipe', backref='user', lazy=True)

    
    serialize_rules = ('-recipes.user', '-_password_hash')

     
    @hybrid_property
    def password_hash(self):
        return self._password_hash

    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)

   
    @validates('email')
    def validate_email(self, key, email):
        if '@' not in email:
            raise ValueError("Provided email is invalid.")
        return email

    @validates('username')
    def validate_username(self, key, username):
        if len(username) < 3:
            raise ValueError("Username must be at least 3 characters long.")
        return username


class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    
    serialize_rules = ('-user.recipes',)

   
    @validates('title')
    def validate_title(self, key, title):
        if len(title) < 3:
            raise ValueError("Title must be at least 3 characters long.")
        return title

    @validates('minutes_to_complete')
    def validate_minutes_to_complete(self, key, minutes):
        if minutes <= 0:
            raise ValueError("Minutes to complete must be greater than 0.")
        return minutes

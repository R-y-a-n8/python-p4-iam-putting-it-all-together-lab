#!/usr/bin/env python3

from flask import Flask, request, session, jsonify
from flask_restful import Resource, Api
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Recipe  # Now import after initializing db
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Replace with a strong secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'  # Add your DB URI here
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # To disable the modification tracking feature
db.init_app(app)  # Initialize the app with db

api = Api(app)

# Root route to test if the app is running
@app.route('/')
def home():
    return "Welcome to the Recipe App!"

class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")

        # Password validation
        if len(password) < 6:
            return {"error": "Password must be at least 6 characters long."}, 422

        # Create a hashed password
        hashed_password = generate_password_hash(password)

        try:
            user = User(username=username, password_hash=hashed_password, image_url=image_url, bio=bio)
            db.session.add(user)
            db.session.commit()

            session["user_id"] = user.id
            return jsonify({
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }), 201
        except IntegrityError:
            db.session.rollback()
            return {"error": "Username must be unique."}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if user_id:
            user = User.query.get(user_id)
            if user:
                return jsonify({
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }), 200
        return {"error": "Unauthorized"}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session["user_id"] = user.id
            return jsonify({
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio
            }), 200
        return {"error": "Invalid username or password"}, 401

class Logout(Resource):
    def delete(self):
        if "user_id" in session:
            session.pop("user_id")
            return {}, 204
        return {"error": "Unauthorized"}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")
        if user_id:
            recipes = Recipe.query.all()
            return jsonify([{
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username
                }
            } for recipe in recipes]), 200
        return {"error": "Unauthorized"}, 401

    def post(self):
        user_id = session.get("user_id")
        if user_id:
            data = request.get_json()

            title = data.get("title")
            instructions = data.get("instructions")
            minutes_to_complete = data.get("minutes_to_complete")

            # Recipe validation
            if not title or len(title.strip()) == 0:
                return {"error": "Title is required."}, 422
            if not instructions or len(instructions) < 50:
                return {"error": "Instructions must be at least 50 characters long."}, 422

            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()

            return jsonify({
                "id": recipe.id,
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username
                }
            }), 201
        return {"error": "Unauthorized"}, 401

# Routes for Signup, CheckSession, Login, Logout, and RecipeIndex
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

# Run the app
if __name__ == '__main__':
    app.run(port=5555, debug=True)

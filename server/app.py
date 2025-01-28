#!/usr/bin/env python3

from flask import request, session, jsonify, Flask
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from config import app, db, api
from models import User, Recipe

# Adding a home route for testing
@app.route('/')
def home():
    return 'Hello, World!'

class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")
        image_url = data.get("image_url")
        bio = data.get("bio")

        try:
            user = User(username=username, image_url=image_url, bio=bio)
            user.password_hash = password  
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
        if user and user.authenticate(password):
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

            if not title or not instructions or len(instructions) < 50:
                return {
                    "error": "Invalid recipe. Title and instructions (at least 50 characters) are required."
                }, 422

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

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)


from flask import request, session, jsonify
from flask_restful import Resource
from models import User, Recipe
from extensions import db

class Signup(Resource):
    def post(self):
        data = request.get_json()
        try:
            user = User(
                username=data['username'],
                password_hash=data['password'],
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(), 201
        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422
        except Exception as e:
            db.session.rollback()
            return {'errors': ['An error occurred']}, 500

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
        user = User.query.get(user_id)
        if not user:
            return {'error': 'User not found'}, 404
        return user.to_dict(), 200

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and user.authenticate(data['password']):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        if 'user_id' not in session:
            return {'error': 'Unauthorized'}, 401
        session.pop('user_id')
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        if 'user_id' not in session:
            return {'error': 'Unauthorized'}, 401
        recipes = Recipe.query.all()
        return [recipe.to_dict() for recipe in recipes], 200
    
    def post(self):
        if 'user_id' not in session:
            return {'error': 'Unauthorized'}, 401
        data = request.get_json()
        try:
            recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=session['user_id']
            )
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(), 201
        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422
        except Exception as e:
            db.session.rollback()
            return {'errors': ['An error occurred']}, 500
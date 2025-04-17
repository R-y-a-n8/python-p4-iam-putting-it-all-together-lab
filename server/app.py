#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json()
        
        # Check for required fields
        required_fields = ['username', 'password', 'image_url', 'bio']
        missing_fields = [field for field in required_fields if field not in data]
        
        if missing_fields:
            return {'errors': [f'{field} is required' for field in missing_fields]}, 422

        username = data['username']
        password = data['password']
        image_url = data['image_url']
        bio = data['bio']

        try:
            new_user = User(
                username=username,
                image_url=image_url,
                bio=bio
            )
            new_user.password_hash = password  # This will use the setter to hash the password

            db.session.add(new_user)
            db.session.commit()
            
            session['user_id'] = new_user.id
            return new_user.to_dict(), 201
        
        except IntegrityError:
            db.session.rollback()
            return {'errors': ['Username already exists']}, 422
        
        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422
        
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error during signup: {str(e)}")
            return {'errors': ['An error occurred during signup']}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            return user.to_dict(), 200
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session.pop('user_id')
            return {}, 204
        return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
        
        recipes = Recipe.query.all()
        return [recipe.to_dict() for recipe in recipes], 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        data = request.get_json()
        try:
            recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(), 201
        except ValueError as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422
        except KeyError as e:
            db.session.rollback()
            return {'errors': [f'{str(e)} is required']}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
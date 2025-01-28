#!/usr/bin/env python3

from random import randint, choice as rc
from faker import Faker
from app import app
from models import db, Recipe, User

fake = Faker()

with app.app_context():

    print("Deleting all records...")
    Recipe.query.delete()
    User.query.delete()

    # Create sample users
    users = []
    for _ in range(5):
        user = User(
            username=fake.user_name(),
            email=fake.email(),
            password_hash=fake.password(),
            bio=fake.text(max_nb_chars=200)
        )
        users.append(user)

    db.session.add_all(users)
    db.session.commit()

    # Create sample recipes
    recipes = []
    for user in users:
        for _ in range(3):
            recipe = Recipe(
                title=fake.sentence(nb_words=4),
                instructions=fake.text(max_nb_chars=200),
                minutes_to_complete=randint(20, 120),
                user_id=user.id
            )
            recipes.append(recipe)

    db.session.add_all(recipes)
    db.session.commit()

    print("Database seeded!")

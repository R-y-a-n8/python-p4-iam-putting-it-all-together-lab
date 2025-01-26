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

    print("Creating users...")

    
    users = []
    usernames = []

    for i in range(20):
        username = fake.first_name()
        while username in usernames:  
            username = fake.first_name()
        usernames.append(username)

        user = User(
            username=username,
            email=fake.email(),
        )
        user.password_hash = f"{username}password"  
        users.append(user)

    db.session.add_all(users)

    print("Creating recipes...")

    
    recipes = []
    for i in range(100):
        recipe = Recipe(
            title=fake.sentence(nb_words=3).rstrip('.'),
            instructions=fake.paragraph(nb_sentences=8),
            minutes_to_complete=randint(15, 90),
            user=rc(users),  
        )
        recipes.append(recipe)

    db.session.add_all(recipes)

    db.session.commit()
    print("Seeding complete.")

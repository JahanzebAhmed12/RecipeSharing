from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default='User')
    name = db.Column(db.String(100))
    blocked = db.Column(db.Boolean, default=False)

class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    ingredients = db.Column(db.Text, nullable=False)
    steps = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    cooking_time = db.Column(db.Integer)
    servings = db.Column(db.Integer)
    difficulty = db.Column(db.String(20))
    image_url = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='recipes')
    approved = db.Column(db.Boolean, default=False)
    dietary_preference = db.Column(db.String(20))
    popularity = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_published = db.Column(db.Boolean, default=True)
    is_reported = db.Column(db.Boolean, default=False)

class Favourite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'))
    __table_args__ = (db.UniqueConstraint('user_id', 'recipe_id', name='unique_fav'),)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'))
    rating = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    approved = db.Column(db.Boolean, default=True)
    notification_sent = db.Column(db.Boolean, default=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'recipe_id', name='unique_review'),) 
    
    # Add relationships
    user = db.relationship('User', backref='reviews')
    recipe = db.relationship('Recipe', backref='recipe_reviews')
    
    def get_recipe(self):
        return Recipe.query.get(self.recipe_id)
        
    def get_author(self):
        return User.query.get(self.user_id)

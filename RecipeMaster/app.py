from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies, set_access_cookies
from flask_wtf.csrf import CSRFProtect, generate_csrf
from functools import wraps
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from models import db, User, Recipe, Favourite, Review
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer
from threading import Thread
import uuid
from sqlalchemy import or_

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-key-change-me')

# Disable CSRF protection
app.config['WTF_CSRF_ENABLED'] = False
# Initialize CSRF with checks disabled
csrf = CSRFProtect()
csrf.init_app(app)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'super-secret-jwt-key-change-me')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///recipemaster.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Replace with your Gmail
app.config['MAIL_PASSWORD'] = 'your_app_password'     # Use App Password for Gmail
db.init_app(app)
jwt = JWTManager(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def send_email(subject, recipients, body):
    msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=recipients)
    msg.body = body
    mail.send(msg)


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # First try to get user from JWT
        try:
            user_id = get_jwt_identity()
            if user_id:
                user = User.query.get(user_id)
                if user and user.role == 'Admin':
                    # Store user info in session for template context
                    session['user_id'] = user.id
                    session['role'] = user.role
                    session['name'] = user.name
                    return fn(*args, **kwargs)
        except RuntimeError:
            pass  # JWT not available, try session
            
        # If JWT not available or invalid, try session
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user and user.role == 'Admin':
                return fn(*args, **kwargs)
        
        # If we get here, user is not authenticated or not an admin
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"message": "Admin access required"}), 403
            
        flash('Admin access required', 'error')
        return redirect(url_for('login'))
    return wrapper

# Admin dashboard route
@app.route('/admin')
@admin_required
def admin_dashboard():
    # Get all users and recipes
    users = User.query.all()
    recipes = Recipe.query.all()
    
    # Get current user from session (set by admin_required decorator)
    current_user = None
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])
    
    return render_template('admin_dashboard.html',
                         users=users,
                         recipes=recipes,
                         current_user=current_user)

# Admin users management
@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.name.asc()).all()
    return render_template('admin_users.html', users=users, now=datetime.utcnow())

@app.route('/admin/user/<int:user_id>/block', methods=['POST'])
@admin_required
def admin_block_user(user_id):
    if request.method == 'POST':
        user = User.query.get_or_404(user_id)
        if user.is_admin:
            return jsonify({'error': 'Cannot block admin users'}), 403
        user.is_active = False
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/admin/user/<int:user_id>/unblock', methods=['POST'])
@admin_required
def admin_unblock_user(user_id):
    if request.method == 'POST':
        user = User.query.get_or_404(user_id)
        if user.is_admin:
            return jsonify({'error': 'Cannot modify admin users'}), 403
        user.is_active = True
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    if request.method == 'POST':
        user = User.query.get_or_404(user_id)
        if user.is_admin:
            return jsonify({'error': 'Cannot delete admin users'}), 403
        
        # Delete user's recipes, favorites, and reviews
        Recipe.query.filter_by(user_id=user.id).delete()
        Favourite.query.filter_by(user_id=user.id).delete()
        Review.query.filter_by(user_id=user.id).delete()
        
        # Delete the user
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'success': True})
    return jsonify({'error': 'Method not allowed'}), 405

# Admin recipes management
@app.route('/admin/recipes')
@admin_required
def admin_recipes():
    status = request.args.get('status', 'all')
    query = Recipe.query.options(db.joinedload(Recipe.user))
    
    if status == 'published':
        query = query.filter(Recipe.is_published == True)
    elif status == 'draft':
        query = query.filter(Recipe.is_published == False)
    elif status == 'reported':
        query = query.filter(Recipe.is_reported == True)
    
    recipes = query.order_by(Recipe.created_at.desc()).all()
    return render_template('admin_recipes.html', recipes=recipes, now=datetime.utcnow())

@app.route('/admin/recipe/<int:recipe_id>/publish', methods=['POST'])
@admin_required
def admin_publish_recipe(recipe_id):
    if request.method == 'POST':
        recipe = Recipe.query.get_or_404(recipe_id)
        recipe.is_published = True
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/admin/recipe/<int:recipe_id>/unpublish', methods=['POST'])
@admin_required
def admin_unpublish_recipe(recipe_id):
    if request.method == 'POST':
        recipe = Recipe.query.get_or_404(recipe_id)
        recipe.is_published = False
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/admin/recipe/<int:recipe_id>/resolve-report', methods=['POST'])
@admin_required
def admin_resolve_report(recipe_id):
    if request.method == 'POST':
        recipe = Recipe.query.get_or_404(recipe_id)
        recipe.is_reported = False
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/admin/recipe/<int:recipe_id>/delete', methods=['POST'])
@admin_required
def admin_delete_recipe(recipe_id):
    if request.method == 'POST':
        recipe = Recipe.query.get_or_404(recipe_id)
        
        # Delete associated favorites and reviews
        Favourite.query.filter_by(recipe_id=recipe.id).delete()
        Review.query.filter_by(recipe_id=recipe.id).delete()
        
        # Delete the recipe
        db.session.delete(recipe)
        db.session.commit()
        
        return jsonify({'success': True})
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/')
def home():
    # Get featured recipes (most rated/reviewed recipes)
    featured_recipes = db.session.query(Recipe)\
        .join(Review, Recipe.id == Review.recipe_id, isouter=True)\
        .filter(Recipe.is_published == True)\
        .group_by(Recipe.id)\
        .order_by(db.func.avg(Review.rating).desc().nullslast(), Recipe.popularity.desc())\
        .limit(6).all()
    
    # Calculate average ratings for featured recipes
    recipe_list = []
    for recipe in featured_recipes:
        reviews = Review.query.filter_by(recipe_id=recipe.id, approved=True).all()
        avg_rating = round(sum(r.rating for r in reviews) / len(reviews), 1) if reviews else 0
        author = User.query.get(recipe.user_id)
        
        recipe_list.append({
            'id': recipe.id,
            'title': recipe.title,
            'description': recipe.description,
            'category': recipe.category,
            'cooking_time': recipe.cooking_time,
            'image_url': recipe.image_url,
            'avg_rating': avg_rating,
            'author_name': author.name if author else 'Unknown'
        })
    
    return render_template('index.html', featured_recipes=recipe_list)

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    if not query:
        return redirect(url_for('recipes'))  # Changed from 'browse_recipes' to 'recipes'
        
    # Search in recipe title, description, and ingredients
    recipes = Recipe.query.filter(
        (Recipe.title.ilike(f'%{query}%')) |
        (Recipe.description.ilike(f'%{query}%')) |
        (Recipe.ingredients.ilike(f'%{query}%'))
    ).all()
    
    # Format recipes for the template
    recipe_list = []
    for r in recipes:
        author = User.query.get(r.user_id)
        recipe_list.append({
            'id': r.id,
            'title': r.title,
            'description': r.description,
            'category': r.category,
            'dietary_preference': r.dietary_preference,
            'cooking_time': r.cooking_time,
            'image_url': r.image_url,
            'popularity': r.popularity,
            'author_name': author.name if author else 'Unknown',
            'favourited': False  # You can implement this based on user's favorites
        })
    
    return render_template('recipes.html', recipes=recipe_list, search_query=query)

@app.route('/register', methods=['GET', 'POST'])
def register():
    import re
    if 'user_id' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        name = request.form['name']
        # Email format validation
        email_regex = r'^\S+@\S+\.\S+$'
        if not re.match(email_regex, email):
            flash('Invalid email format')
            return redirect(url_for('register'))
        # Password match
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))
        # Password strength (min 6 chars, at least 1 digit, 1 letter)
        if len(password) < 6 or not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
            flash('Password must be at least 6 characters and contain both letters and numbers')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        user = User(email=email, password=hashed_password, name=name)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.blocked:
            flash('Your account is blocked. Contact admin.')
        elif user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['name'] = user.name
            # Create JWT token
            access_token = create_access_token(identity=str(user.id))
            
            # Create response with JWT cookie
            resp = redirect(url_for('admin_dashboard' if user.role == 'Admin' else 'home'))
            set_access_cookies(resp, access_token)
            return resp
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    resp = redirect(url_for('home'))
    unset_jwt_cookies(resp)
    session.clear()
    return resp

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    user = User.query.get(user_id)
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_profile':
            new_name = request.form['name']
            new_email = request.form['email']
            if new_email != user.email and User.query.filter_by(email=new_email).first():
                flash('Email already in use.')
            else:
                user.name = new_name
                user.email = new_email
                db.session.commit()
                flash('Profile updated!')
        elif action == 'change_password':
            current_password = request.form['current_password']
            new_password = request.form['new_password']
            confirm_new_password = request.form['confirm_new_password']
            if not check_password_hash(user.password, current_password):
                flash('Current password is incorrect.')
            elif new_password != confirm_new_password:
                flash('New passwords do not match.')
            elif len(new_password) < 6:
                flash('New password must be at least 6 characters.')
            else:
                user.password = generate_password_hash(new_password)
                db.session.commit()
                flash('Password changed successfully!')
        elif action == 'delete_account':
            db.session.delete(user)
            db.session.commit()
            flash('Account deleted.')
            resp = redirect(url_for('home'))
            unset_jwt_cookies(resp)
            session.clear()
            return resp
    return render_template('profile.html', user=user)

UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/add-recipe', methods=['GET', 'POST'])
def add_recipe():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        category = request.form['category']
        dietary_preference = request.form['dietary_preference']
        cooking_time = request.form.get('cooking_time')
        ingredients = '\n'.join([v for k, v in request.form.items() if k.startswith('ingredient') and v])
        steps = '\n'.join([v for k, v in request.form.items() if k.startswith('instruction') and v])
        image_url = ''
        if 'image' in request.files:
            image = request.files['image']
            if image and allowed_file(image.filename):
                filename = secure_filename(str(uuid.uuid4()) + '_' + image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_url = f'/static/uploads/{filename}'
        recipe = Recipe(
            title=title,
            description=description,
            category=category,
            dietary_preference=dietary_preference,
            cooking_time=int(cooking_time) if cooking_time else None,
            ingredients=ingredients,
            steps=steps,
            image_url=image_url,
            user_id=user_id,
            approved=False
        )
        db.session.add(recipe)
        db.session.commit()
        flash('Recipe submitted for review!')
        return redirect(url_for('recipes'))  # Changed from 'browse_recipes' to 'recipes'
    return render_template('add_edit_recipe.html')

@app.route('/favourite/<int:recipe_id>', methods=['POST'])
@jwt_required()
def add_favourite(recipe_id):
    user_id = get_jwt_identity()
    if not Favourite.query.filter_by(user_id=user_id, recipe_id=recipe_id).first():
        fav = Favourite(user_id=user_id, recipe_id=recipe_id)
        db.session.add(fav)
        db.session.commit()
    return '', 204

@app.route('/unfavourite/<int:recipe_id>', methods=['POST'])
@jwt_required()
def remove_favourite(recipe_id):
    user_id = get_jwt_identity()
    fav = Favourite.query.filter_by(user_id=user_id, recipe_id=recipe_id).first()
    if fav:
        db.session.delete(fav)
        db.session.commit()
    return '', 204

@app.route('/recipes', endpoint='recipes')
def browse_recipes():
    user_id = None
    user = None
    fav_ids = set()
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id) if user_id else None
        if user_id:
            fav_ids = set(f.recipe_id for f in Favourite.query.filter_by(user_id=user_id).all())
    except Exception:
        pass
    if user and user.role == 'Admin':
        query = Recipe.query
    else:
        query = Recipe.query.filter_by(approved=True)
    # Search filters
    q = request.args.get('q', '').strip()
    if q:
        query = query.filter(or_(Recipe.title.ilike(f'%{q}%'), Recipe.description.ilike(f'%{q}%')))
    ingredients = request.args.get('ingredients', '').strip()
    if ingredients:
        for ing in ingredients.split(','):
            ing = ing.strip()
            if ing:
                query = query.filter(Recipe.ingredients.ilike(f'%{ing}%'))
    category = request.args.get('category', '').strip()
    if category:
        query = query.filter(Recipe.category.ilike(f'%{category}%'))
    cooking_time = request.args.get('cooking_time', '').strip()
    if cooking_time.isdigit():
        query = query.filter(Recipe.cooking_time <= int(cooking_time))
    dietary_preference = request.args.get('dietary_preference', '').strip()
    if dietary_preference:
        query = query.filter(Recipe.dietary_preference == dietary_preference)
    sort = request.args.get('sort', 'recent')
    if sort == 'popularity':
        if hasattr(Recipe, 'popularity'):
            query = query.order_by(Recipe.popularity.desc())
        else:
            query = query.order_by(Recipe.id.desc())
    else:
        query = query.order_by(Recipe.id.desc())
    recipes = query.all()
    # Attach author name to each recipe
    recipe_list = []
    for r in recipes:
        author = User.query.get(r.user_id)
        recipe_list.append({
            'id': r.id,
            'title': r.title,
            'description': r.description,
            'category': r.category,
            'dietary_preference': r.dietary_preference,
            'cooking_time': r.cooking_time,
            'image_url': r.image_url,
            'popularity': r.popularity,
            'author_name': author.name if author else 'Unknown',
            'favourited': r.id in fav_ids,
        })
    return render_template('recipes.html', recipes=recipe_list)

def send_comment_notification(review):
    """Send email notification to recipe author when a new review is added"""
    try:
        recipe = Recipe.query.get(review.recipe_id)
        if recipe and recipe.user_id:
            author = User.query.get(recipe.user_id)
            reviewer = User.query.get(review.user_id)
            
            if author and author.email and reviewer:
                subject = f"New Review on Your Recipe: {recipe.title}"
                body = f"""
Hello {author.name},

{reviewer.name} has left a new review on your recipe "{recipe.title}".

Rating: {'⭐' * review.rating} ({review.rating}/5)
Review: {review.text}

You can view the full review at: {url_for('recipe_detail', recipe_id=recipe.id, _external=True)}

Best regards,
RecipeMaster Team
                """
                send_email(subject, [author.email], body)
    except Exception as e:
        print(f"Failed to send notification email: {e}")

# Add or edit review
@app.route('/recipe/<int:recipe_id>/review', methods=['POST'])
def add_or_edit_review(recipe_id):
    # Check if user is logged in via session
    if 'user_id' not in session:
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"msg": "Authentication required"}), 401
        flash('Please log in to submit a review', 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    rating = int(request.form.get('rating'))
    text = request.form.get('text', '').strip()
    
    # Validate rating
    if not 1 <= rating <= 5:
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"msg": "Invalid rating"}), 400
        flash('Invalid rating')
        return redirect(url_for('recipe_detail', recipe_id=recipe_id))
        
    # Check if user has already reviewed this recipe
    review = Review.query.filter_by(user_id=user_id, recipe_id=recipe_id).first()
    
    if review:
        # Update existing review
        review.rating = rating
        review.text = text
        review.timestamp = datetime.utcnow()
        review.approved = False  # Require re-approval for edited reviews
        db.session.commit()
        message = 'Review updated successfully and is pending approval'
    else:
        # Create new review
        review = Review(
            user_id=user_id,
            recipe_id=recipe_id,
            rating=rating,
            text=text,
            approved=False  # Require approval for new reviews
        )
        db.session.add(review)
        db.session.commit()
        message = 'Review submitted successfully and is pending approval'
        
        # Send notification for new reviews only
        try:
            send_comment_notification(review)
        except:
            pass  # Don't fail if email notification fails
    
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({"msg": message}), 200
    
    flash(message)
    return redirect(url_for('recipe_detail', recipe_id=recipe_id))

@app.route('/recipe/<int:recipe_id>')
def recipe_detail(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    recipe.popularity += 1
    db.session.commit()
    
    user_id = None
    user = None
    is_admin = False
    try:
        user_id = get_jwt_identity()
        user = User.query.get(user_id) if user_id else None
        is_admin = user and user.role == 'Admin'
    except Exception:
        pass
    
    is_owner = user_id == recipe.user_id if user_id else False
    
    if is_admin:
        reviews = Review.query.filter_by(recipe_id=recipe_id).order_by(Review.timestamp.desc()).all()
    else:
        reviews = Review.query.filter_by(recipe_id=recipe_id, approved=True).order_by(Review.timestamp.desc()).all()
    
    avg_rating = round(sum(r.rating for r in reviews) / len(reviews), 1) if reviews else None
    
    user_review = None
    if user_id:
        user_review = Review.query.filter_by(user_id=user_id, recipe_id=recipe_id).first()
    
    return render_template('recipe_detail.html', 
                         recipe=recipe, 
                         is_owner=is_owner, 
                         reviews=reviews, 
                         avg_rating=avg_rating, 
                         user_review=user_review, 
                         is_admin=is_admin)

@app.route('/edit-recipe/<int:recipe_id>', methods=['GET', 'POST'])
def edit_recipe(recipe_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    recipe = Recipe.query.get_or_404(recipe_id)
    if recipe.user_id != user_id:
        flash('You can only edit your own recipes.')
        return redirect(url_for('recipes'))  # Changed from 'browse_recipes' to 'recipes'
    if request.method == 'POST':
        recipe.title = request.form['title']
        recipe.description = request.form['description']
        recipe.category = request.form['category']
        recipe.dietary_preference = request.form['dietary_preference']
        recipe.cooking_time = request.form.get('cooking_time')
        recipe.ingredients = '\n'.join([v for k, v in request.form.items() if k.startswith('ingredient') and v])
        recipe.steps = '\n'.join([v for k, v in request.form.items() if k.startswith('instruction') and v])
        if 'image' in request.files:
            image = request.files['image']
            if image and allowed_file(image.filename):
                filename = secure_filename(str(uuid.uuid4()) + '_' + image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                recipe.image_url = f'/static/uploads/{filename}'
        recipe.approved = False  # Needs re-approval after edit
        db.session.commit()
        flash('Recipe updated and submitted for review!')
        return redirect(url_for('recipes'))  # Changed from 'browse_recipes' to 'recipes'
    return render_template('add_edit_recipe.html', recipe=recipe)

@app.route('/delete-recipe/<int:recipe_id>', methods=['POST'])
def delete_recipe_user(recipe_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    recipe = Recipe.query.get_or_404(recipe_id)
    if recipe.user_id != user_id:
        flash('You can only delete your own recipes.')
        return redirect(url_for('recipes'))  # Changed from 'browse_recipes' to 'recipes'
    db.session.delete(recipe)
    db.session.commit()
    flash('Recipe deleted.')
    return redirect(url_for('recipes'))  # Changed from 'browse_recipes' to 'recipes'

@app.route('/admin/user/<int:user_id>/block', methods=['POST'])
@admin_required
def block_user(user_id):
    from flask import request
    user = User.query.get(user_id)
    if user:
        data = request.get_json()
        user.blocked = bool(data.get('block', False))
        db.session.commit()
        return '', 204
    return '', 404

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return '', 204
    return '', 404

@app.route('/admin/recipe/<int:recipe_id>/approve', methods=['POST'])
@admin_required
def approve_recipe(recipe_id):
    recipe = Recipe.query.get(recipe_id)
    if recipe:
        recipe.approved = True
        db.session.commit()
        return '', 204
    return '', 404

@app.route('/admin/recipe/<int:recipe_id>/delete', methods=['POST'])
@admin_required
def delete_recipe(recipe_id):
    recipe = Recipe.query.get(recipe_id)
    if recipe:
        db.session.delete(recipe)
        db.session.commit()
        return '', 204
    return '', 404

@app.route('/admin/reviews')
@admin_required
def admin_reviews():
    reviews = Review.query.order_by(Review.timestamp.desc()).all()
    review_list = []
    for r in reviews:
        user = User.query.get(r.user_id)
        recipe = Recipe.query.get(r.recipe_id)
        review_list.append({
            'id': r.id,
            'user_name': user.name if user else 'Unknown',
            'recipe_id': r.recipe_id,
            'recipe_title': recipe.title if recipe else 'Unknown',
            'rating': r.rating,
            'text': r.text,
            'timestamp': r.timestamp,
            'approved': r.approved,
        })
    return render_template('admin_reviews.html', reviews=review_list)

@app.route('/admin/review/<int:review_id>/approve', methods=['POST'])
@admin_required
def approve_review(review_id):
    review = Review.query.get(review_id)
    if review:
        review.approved = True
        db.session.commit()
        return '', 204
    return '', 404

@app.route('/admin/review/<int:review_id>/unapprove', methods=['POST'])
@admin_required
def unapprove_review(review_id):
    review = Review.query.get(review_id)
    if review:
        review.approved = False
        db.session.commit()
        return '', 204
    return '', 404

@app.route('/admin/review/<int:review_id>/delete', methods=['POST'])
@admin_required
def delete_review(review_id):
    review = Review.query.get(review_id)
    if review:
        db.session.delete(review)
        db.session.commit()
        return '', 204
    return '', 404

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(user.email, salt='reset-password')
            link = url_for('reset_password_token', token=token, _external=True)
            send_email(
                subject='Password Reset Request',
                recipients=[user.email],
                body=f'Click the link to reset your password: {link}\nThis link is valid for 1 hour.'
            )
            flash('Password reset link sent to your email.')
        else:
            flash('If the email exists, a reset link has been sent.')
    return render_template('reset_password_request.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        email = serializer.loads(token, salt='reset-password', max_age=3600)
    except Exception:
        flash('The reset link is invalid or has expired.')
        return redirect(url_for('reset_password_request'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Invalid user.')
        return redirect(url_for('reset_password_request'))
    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']
        if password != confirm:
            flash('Passwords do not match.')
        elif len(password) < 6:
            flash('Password must be at least 6 characters.')
        else:
            user.password = generate_password_hash(password)
            db.session.commit()
            flash('Password reset successful. You can now log in.')
            return redirect(url_for('login'))
    return render_template('reset_password_form.html', token=token)

@app.context_processor
def inject_user():
    from flask_jwt_extended import get_jwt_identity
    from datetime import datetime
    
    context = {
        'logged_in': False,
        'user_name': None,
        'csrf_token': generate_csrf,
        'now': datetime.utcnow(),
        'current_user': None
    }
    
    # Check session-based authentication
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            context.update({
                'logged_in': True,
                'user_name': user.name,
                'current_user': user
            })
    # Check JWT-based authentication
    elif 'Authorization' in request.headers:
        try:
            user_id = get_jwt_identity()
            if user_id:
                user = User.query.get(user_id)
                if user:
                    context.update({
                        'logged_in': True,
                        'user_name': user.name,
                        'current_user': user
                    })
        except Exception:
            pass
            
    return context













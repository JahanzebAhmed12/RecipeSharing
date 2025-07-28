import os
from dotenv import load_dotenv
from app import app, db, User
from werkzeug.security import generate_password_hash

def create_admin_user():
    """Create admin user if it doesn't exist"""
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@example.com')
    admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
    admin_name = os.getenv('ADMIN_NAME', 'Admin')
    
    if not User.query.filter_by(role='Admin').first():
        admin = User(
            email=admin_email,
            password=generate_password_hash(admin_password),
            name=admin_name,
            role='Admin'
        )
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user created with email: {admin_email}")
    else:
        print("Admin user already exists")

if __name__ == "__main__":
    # Load environment variables from .env file if it exists
    load_dotenv()
    
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Create admin user
        create_admin_user()
    
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re

# Initialize Flask app
app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "").replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session configuration
app.config['SECRET_KEY'] = os.environ.get(
    "SECRET_KEY",
    "musicianhub-stable-secret-key"
)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS

# Initialize extensions
db = SQLAlchemy(app)

# Initialize LoginManager with proper configuration
login_manager = LoginManager()
login_manager.init_app(app)

# ✅ CRITICAL FIX 2 — LoginManager SETTINGS
login_manager.login_view = None  # No redirect for API
login_manager.session_protection = "strong"  # Better session security

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ✅ RECOMMENDED FIX 3 — REMOVED CORS(app, ...) duplication
# Keeping only the manual CORS headers (more control)

# CORS headers
@app.after_request
def after_request(response):
    origin = request.headers.get("Origin", "")
    allowed_origins = ["http://localhost:3000", "https://your-frontend-domain.com"]  # Add your actual frontend URLs
    
    if origin in allowed_origins:
        response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    return response

# API Routes
@app.route("/api/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        
        if not username or not email or not password:
            return jsonify({"error": "All fields are required"}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already exists"}), 400
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        # ✅ CRITICAL FIX 1 — Added remember=True
        login_user(new_user, remember=True)
        
        return jsonify({
            "message": "Registration successful",
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # ✅ CRITICAL FIX 1 — Added remember=True
            login_user(user, remember=True)
            return jsonify({
                "message": "Login successful",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email
                }
            }), 200
        else:
            return jsonify({"error": "Invalid username or password"}), 401
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successful"}), 200

# ✅ KEEP THIS ROUTE - Required for session restore
@app.route("/api/me")
@login_required
def me():
    return jsonify({
        "logged_in": True,
        "username": current_user.username,
        "id": current_user.id,
        "email": current_user.email
    })

# Health check route
@app.route("/api/health")
def health():
    return jsonify({"status": "healthy"}), 200

# ✅ OPTIONAL: Keep seed_database function but never call it automatically
def seed_database():
    """Seed database with initial data (ONLY RUN MANUALLY WHEN NEEDED)"""
    try:
        # Check if admin exists
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin_user = User(username="admin", email="admin@example.com")
            admin_user.set_password("admin123")
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Database seeded with admin user")
        else:
            print("⚠️ Admin user already exists")
    except Exception as e:
        print(f"❌ Seeding failed: {e}")
        db.session.rollback()

# ✅ SAFE INIT - ONLY THIS (NO DROP_ALL, NO AUTO-SEED)
with app.app_context():
    db.create_all()
    print("✅ Database tables created (if they don't exist)")

# Run server
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # ✅ RECOMMENDED FIX 4 — Removed debug=True for production safety
    app.run(host="0.0.0.0", port=port)

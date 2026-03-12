
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, current_user
from datetime import datetime
import os
import cloudinary
import cloudinary.uploader

app = Flask(__name__)

database_url = os.environ.get("DATABASE_URL", "sqlite:///app.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "musicianhub-secret")

db = SQLAlchemy(app)

cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET")
)

login_manager = LoginManager(app)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile_picture = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    media_url = db.Column(db.String(500))
    media_type = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "media_url": self.media_url,
            "media_type": self.media_type,
            "created_at": self.created_at.isoformat(),
            "author": self.user_id
        }

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/search")
def search():
    query = request.args.get("q", "")
    results = {"users": [], "posts": []}

    if query:
        users = User.query.filter(User.username.ilike(f"%{query}%")).limit(20).all()
        posts = Post.query.filter(
            (Post.title.ilike(f"%{query}%")) |
            (Post.content.ilike(f"%{query}%"))
        ).limit(20).all()
    else:
        users = User.query.limit(20).all()
        posts = Post.query.limit(20).all()

    results["users"] = [
        {
            "id": u.id,
            "username": u.username,
            "profile_picture": u.profile_picture
        } for u in users
    ]

    results["posts"] = [p.to_dict() for p in posts]

    return jsonify(results)

@app.route("/api/create_post", methods=["POST"])
@login_required
def create_post():
    title = request.form.get("title")
    content = request.form.get("content")
    file = request.files.get("file")

    media_url = None
    media_type = None

    if file:
        upload = cloudinary.uploader.upload(file)
        media_url = upload["secure_url"]
        media_type = file.content_type

    post = Post(
        title=title,
        content=content,
        media_url=media_url,
        media_type=media_type,
        user_id=current_user.id
    )

    db.session.add(post)
    db.session.commit()

    return jsonify({"success": True})

@app.route("/api/posts")
def get_posts():
    posts = Post.query.order_by(Post.created_at.desc()).limit(50).all()
    return jsonify([p.to_dict() for p in posts])

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

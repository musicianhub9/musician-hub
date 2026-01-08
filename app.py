from flask import Flask, render_template, request, jsonify, make_response, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import uuid
import socket
import cloudinary
import cloudinary.uploader

# ✅ 1. Initialize SQLAlchemy at the TOP
db = SQLAlchemy()

app = Flask(__name__)

# ✅ 2. POSTGRES DATABASE Configuration
database_url = os.environ.get("DATABASE_URL")

if not database_url:
    raise RuntimeError("DATABASE_URL is missing")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize db with app
db.init_app(app)

# ✅ 3. Cloudinary Configuration
cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET")
)

# Other Configurations
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY',
    'musicianhub-secret-key-2024'
)

# ✅ IMPROVED: Session cookie settings - secure only on Render
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = bool(os.environ.get("RENDER"))  # ✅ Handles "1" or "true"

# Safe file upload limit
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp3', 'wav', 'mp4', 'mov'}

login_manager = LoginManager(app)
login_manager.login_view = 'login_page'

# Get local IP address
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

local_ip = get_local_ip()

# ✅ CORS headers middleware
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# -------------------------------
# MODELS
# -------------------------------
class User(UserMixin, db.Model):
    __tablename__ = 'users'  # ✅ CHANGED from 'user' to 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    instrument = db.Column(db.String(100), default='')
    bio = db.Column(db.Text, default='')
    location = db.Column(db.String(100), default='')
    profile_picture = db.Column(db.String(200), default='')
    user_type = db.Column(db.String(20), default='creator')  # ✅ ADDED: 'creator' or 'listener'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)
    
    # Follow relationships
    following_users = db.relationship(
        'Follow',
        foreign_keys='Follow.follower_id',
        backref='follower_user',
        lazy='dynamic'
    )
    
    follower_users = db.relationship(
        'Follow',
        foreign_keys='Follow.following_id',
        backref='following_user',
        lazy='dynamic'
    )
    
    # Community memberships
    community_memberships = db.relationship(
        'CommunityMember', 
        foreign_keys='CommunityMember.user_id',
        backref='member_user', 
        lazy=True
    )
    
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def to_dict(self):
        # Get actual follow counts
        following_count = Follow.query.filter_by(follower_id=self.id).count()
        follower_count = Follow.query.filter_by(following_id=self.id).count()
        
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'instrument': self.instrument,
            'bio': self.bio,
            'location': self.location,
            'profile_picture': self.profile_picture,
            'user_type': self.user_type,  # ✅ ADDED
            'created_at': self.created_at.strftime('%Y-%m-%d'),
            'post_count': len(self.posts),
            'follower_count': follower_count,
            'following_count': following_count
        }


class Post(db.Model):
    __tablename__ = 'post'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    post_type = db.Column(db.String(50), default='text')
    media_url = db.Column(db.String(500), default='')
    media_type = db.Column(db.String(50), default='')
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ CHANGED to 'users.id'
    community_id = db.Column(db.Integer, db.ForeignKey('community.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    likes = db.Column(db.Integer, default=0)
    shares = db.Column(db.Integer, default=0)
    
    # Relationships
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        # Optimized: Use get instead of query.get
        user = db.session.get(User, self.user_id)
        community = db.session.get(Community, self.community_id) if self.community_id else None
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'post_type': self.post_type,
            'media_url': self.media_url,
            'media_type': self.media_type,
            'user_id': self.user_id,
            'username': user.username if user else 'Unknown',
            'user_instrument': user.instrument if user else '',
            'user_type': user.user_type if user else 'creator',  # ✅ ADDED
            'community_id': self.community_id,
            'community_name': community.name if community else None,
            'likes': self.likes,
            'shares': self.shares,
            'comment_count': len(self.comments),
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
            'time_ago': self.get_time_ago()
        }
    
    def get_time_ago(self):
        now = datetime.utcnow()
        diff = now - self.created_at
        if diff.days > 365:
            return f'{diff.days // 365}y ago'
        if diff.days > 30:
            return f'{diff.days // 30}m ago'
        if diff.days > 0:
            return f'{diff.days}d ago'
        if diff.seconds > 3600:
            return f'{diff.seconds // 3600}h ago'
        if diff.seconds > 60:
            return f'{diff.seconds // 60}m ago'
        return 'Just now'


class Comment(db.Model):
    __tablename__ = 'comment'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ CHANGED to 'users.id'
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        # Optimized: Use get instead of query.get
        user = db.session.get(User, self.user_id)
        return {
            'id': self.id,
            'content': self.content,
            'user_id': self.user_id,
            'username': user.username if user else 'Unknown',
            'user_instrument': user.instrument if user else '',
            'user_type': user.user_type if user else 'creator',  # ✅ ADDED
            'post_id': self.post_id,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M'),
            'time_ago': self.get_time_ago()
        }
    
    def get_time_ago(self):
        now = datetime.utcnow()
        diff = now - self.created_at
        if diff.days > 0:
            return f'{diff.days}d ago'
        if diff.seconds > 3600:
            return f'{diff.seconds // 3600}h ago'
        if diff.seconds > 60:
            return f'{diff.seconds // 60}m ago'
        return 'Just now'


class Message(db.Model):  # ✅ ADDED: Messaging model
    __tablename__ = 'message'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    # ✅ CHANGE #1: REMOVED PostgreSQL CHECK constraint
    # This was removed for PostgreSQL compatibility
    # __table_args__ = (
    #     db.CheckConstraint('''
    #         EXISTS (SELECT 1 FROM users WHERE id = sender_id AND user_type = 'creator') AND
    #         EXISTS (SELECT 1 FROM users WHERE id = receiver_id AND user_type = 'creator')
    #     ''', name='check_both_creators'),
    # )


class Community(db.Model):
    __tablename__ = 'community'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50), default='users')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))  # ✅ CHANGED to 'users.id'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    member_count = db.Column(db.Integer, default=0)
    
    # Relationships
    posts = db.relationship('Post', backref='community', lazy=True)
    members = db.relationship('CommunityMember', backref='community', lazy=True)
    
    def to_dict(self):
        # Optimized: Use get instead of query.get
        creator = db.session.get(User, self.created_by)
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'icon': self.icon,
            'created_by': self.created_by,
            'creator_name': creator.username if creator else 'Unknown',
            'member_count': self.member_count,
            'created_at': self.created_at.strftime('%Y-%m-%d'),
            'pending_requests': len([m for m in self.members if m.status == 'pending'])
        }


class CommunityMember(db.Model):
    __tablename__ = 'community_member'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ CHANGED to 'users.id'
    community_id = db.Column(db.Integer, db.ForeignKey('community.id'), nullable=False)
    
    # Use String instead of Enum for better PostgreSQL compatibility
    status = db.Column(db.String(20), default='pending')  # 'pending', 'secondary', 'primary', 'rejected'
    
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    approved_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # ✅ CHANGED to 'users.id'
    
    # Relationships with explicit foreign_keys
    user = db.relationship('User', foreign_keys=[user_id])
    approver = db.relationship('User', foreign_keys=[approved_by])
    
    # Ensure one membership per user per community
    __table_args__ = (db.UniqueConstraint('user_id', 'community_id', name='unique_membership'),)

    def to_dict(self):
        # Optimized: Use get instead of query.get
        user = db.session.get(User, self.user_id)
        approver = db.session.get(User, self.approved_by) if self.approved_by else None
        return {
            'id': self.id,
            'user_id': self.user_id,
            'community_id': self.community_id,
            'username': user.username if user else 'Unknown',
            'user_instrument': user.instrument if user else '',
            'user_type': user.user_type if user else 'creator',  # ✅ ADDED
            'status': self.status,
            'requested_at': self.requested_at.strftime('%Y-%m-%d %H:%M'),
            'approved_at': self.approved_at.strftime('%Y-%m-%d %H:%M') if self.approved_at else None,
            'approved_by': self.approved_by,
            'approver_name': approver.username if approver else None
        }


class Follow(db.Model):
    __tablename__ = 'follow'
    
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ CHANGED to 'users.id'
    following_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ CHANGED to 'users.id'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Use back_populates instead of backref to avoid naming conflicts
    follower = db.relationship('User', foreign_keys=[follower_id])
    following = db.relationship('User', foreign_keys=[following_id])
    
    # Ensure unique follow relationship
    __table_args__ = (db.UniqueConstraint('follower_id', 'following_id', name='unique_follow'),)


class PostLike(db.Model):
    __tablename__ = 'post_like'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ CHANGED to 'users.id'
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure unique like per user per post
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_like'),)


class PostShare(db.Model):
    __tablename__ = 'post_share'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ CHANGED to 'users.id'
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure unique share per user per post
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_share'),)


class CommunityRequestNotification(db.Model):
    __tablename__ = 'community_request_notification'
    
    id = db.Column(db.Integer, primary_key=True)
    community_id = db.Column(db.Integer, db.ForeignKey('community.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ CHANGED to 'users.id'
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ CHANGED to 'users.id'
    
    # Use String instead of Enum
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'rejected'
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Define relationships with explicit foreign_keys
    community = db.relationship('Community', foreign_keys=[community_id])
    user = db.relationship('User', foreign_keys=[user_id])
    admin = db.relationship('User', foreign_keys=[admin_id])


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ✅ ✅ Create tables (temporarily uncomment for first deployment)
with app.app_context():
    try:
        db.create_all()
        # Set existing users to 'creator' type
        users = User.query.all()
        for user in users:
            if not user.user_type:
                user.user_type = 'creator'
        db.session.commit()
        print("✓ Database tables created successfully")
    except Exception as e:
        print(f"✗ Error creating database tables: {e}")


# -------------------------------
# ROUTES 
# -------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login-page')
def login_page():
    return render_template('index.html')


# -------------------------------
# AUTH API
# -------------------------------
@app.route('/api/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        instrument = data.get('instrument', '')
        # ✅ CHANGE #3: Get user_type from form, default to 'listener'
        user_type = data.get('user_type', 'listener')  # ✅ MODIFIED
        
        if not all([username, email, password]):  # user_type is optional, defaults to 'listener'
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        if user_type not in ['creator', 'listener']:  # ✅ ADDED
            return jsonify({'success': False, 'message': 'Invalid user type'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        user = User(username=username, email=email, instrument=instrument, user_type=user_type)  # ✅ MODIFIED
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Registration successful!', 
            'user': user.to_dict()
        })
    
    except Exception as e:
        print("Registration error:", e)
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500


@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password required'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            login_user(user, remember=True)
            return jsonify({
                'success': True, 
                'message': 'Logged in successfully!', 
                'user': user.to_dict()
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
    
    except Exception as e:
        print("Login error:", e)
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500


@app.route('/api/logout', methods=['GET', 'OPTIONS'])
@login_required
def logout():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully'})


@app.route('/api/user/current', methods=['GET', 'OPTIONS'])
def current_user_info():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    if current_user.is_authenticated:
        return jsonify({'success': True, 'user': current_user.to_dict()})
    return jsonify({'success': False, 'message': 'Not authenticated'}), 401


# -------------------------------
# PROFILE UPDATE API
# -------------------------------
@app.route('/api/users/update', methods=['POST', 'OPTIONS'])
@login_required
def update_profile():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        # Update user fields
        user = current_user
        
        if 'username' in data:
            new_username = data['username']
            # Check if username is available
            if new_username != user.username:
                existing = User.query.filter_by(username=new_username).first()
                if existing:
                    return jsonify({'success': False, 'message': 'Username already exists'}), 400
                user.username = new_username
        
        if 'bio' in data:
            user.bio = data['bio']
        
        if 'instrument' in data:
            user.instrument = data['instrument']
        
        if 'location' in data:
            user.location = data['location']
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Profile updated!',
            'user': user.to_dict()
        })
    
    except Exception as e:
        print("Update error:", e)
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500


# -------------------------------
# POSTS API (WITH CREATOR CHECK)
# -------------------------------
@app.route('/api/posts', methods=['GET', 'POST', 'OPTIONS'])
def posts():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    if request.method == 'GET':
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        user_id = request.args.get('user_id', type=int)
        community_id = request.args.get('community_id', type=int)
        
        query = Post.query
        if user_id:
            query = query.filter_by(user_id=user_id)
        if community_id:
            query = query.filter_by(community_id=community_id)
        
        posts = query.order_by(Post.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        posts_data = [post.to_dict() for post in posts.items]
        
        return jsonify({
            'success': True,
            'posts': posts_data,
            'total': posts.total,
            'pages': posts.pages,
            'current_page': posts.page
        })
    
    elif request.method == 'POST':
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        # ✅ CHANGE #4: Only creators can post
        if current_user.user_type != 'creator':
            abort(403)
        
        # Cloudinary upload logic
        media_url = ''
        media_type = request.form.get('post_type', 'text')
        
        if 'media' in request.files:
            file = request.files['media']
            
            if file and allowed_file(file.filename):
                try:
                    # Upload to Cloudinary
                    result = cloudinary.uploader.upload(
                        file,
                        resource_type="auto"
                    )
                    media_url = result["secure_url"]
                    media_type = result["resource_type"]
                except Exception as e:
                    print(f"Cloudinary upload error: {e}")
                    media_url = ''
                    media_type = request.form.get('post_type', 'text')
            else:
                media_url = ''
                media_type = request.form.get('post_type', 'text')
        else:
            media_url = ''
            media_type = request.form.get('post_type', 'text')
            
        title = request.form.get('title')
        content = request.form.get('content')
        community_id = request.form.get('community_id', type=int)
        
        if not title or not content:
            return jsonify({'success': False, 'message': 'Title and content are required'}), 400
        
        # Check if user can post to community
        if community_id:
            community = Community.query.get_or_404(community_id)
            membership = CommunityMember.query.filter_by(
                user_id=current_user.id,
                community_id=community_id
            ).first()
            
            if not membership or membership.status != 'primary':
                return jsonify({
                    'success': False, 
                    'message': 'You need primary membership to post in this community'
                }), 403
        
        post = Post(
            title=title,
            content=content,
            post_type=request.form.get('post_type', 'text'),
            media_url=media_url,
            media_type=media_type,
            user_id=current_user.id,
            community_id=community_id
        )
        
        db.session.add(post)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Post created!', 'post': post.to_dict()})


@app.route('/api/posts/<int:post_id>/like', methods=['POST', 'OPTIONS'])
@login_required
def like_post(post_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    post = Post.query.get_or_404(post_id)
    existing_like = PostLike.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if existing_like:
        db.session.delete(existing_like)
        post.likes -= 1
        liked = False
    else:
        like = PostLike(user_id=current_user.id, post_id=post_id)
        db.session.add(like)
        post.likes += 1
        liked = True
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'liked': liked,
        'likes': post.likes
    })


@app.route('/api/posts/<int:post_id>/share', methods=['POST', 'OPTIONS'])
@login_required
def share_post(post_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    post = Post.query.get_or_404(post_id)
    
    existing_share = PostShare.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if not existing_share:
        share = PostShare(user_id=current_user.id, post_id=post_id)
        db.session.add(share)
        post.shares += 1
        db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Post shared successfully!',
        'shares': post.shares
    })


@app.route('/api/posts/<int:post_id>/comments', methods=['GET', 'POST', 'OPTIONS'])
def post_comments(post_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    if request.method == 'GET':
        comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at.desc()).all()
        comments_data = [comment.to_dict() for comment in comments]
        
        return jsonify({
            'success': True,
            'comments': comments_data
        })
    
    elif request.method == 'POST':
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        content = data.get('content')
        
        if not content:
            return jsonify({'success': False, 'message': 'Comment content is required'}), 400
        
        comment = Comment(
            content=content,
            user_id=current_user.id,
            post_id=post_id
        )
        
        db.session.add(comment)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Comment added!',
            'comment': comment.to_dict()
        })


@app.route('/api/posts/<int:post_id>', methods=['DELETE', 'OPTIONS'])
@login_required
def delete_post(post_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    post = Post.query.get_or_404(post_id)
    
    if post.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    db.session.delete(post)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Post deleted'})


# -------------------------------
# MESSAGING API (CREATOR-ONLY)
# -------------------------------
@app.route('/api/messages', methods=['GET', 'POST', 'OPTIONS'])
@login_required
def messages():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    if request.method == 'GET':
        # Get conversations for current user
        user_id = current_user.id
        conversations = []
        
        # Get unique users you've messaged or who messaged you
        sent_to = db.session.query(Message.receiver_id).filter_by(sender_id=user_id).distinct().all()
        received_from = db.session.query(Message.sender_id).filter_by(receiver_id=user_id).distinct().all()
        
        user_ids = set([id[0] for id in sent_to] + [id[0] for id in received_from])
        
        for uid in user_ids:
            user = User.query.get(uid)
            if user and user.user_type == 'creator':  # Only show creators
                last_message = Message.query.filter(
                    ((Message.sender_id == user_id) & (Message.receiver_id == uid)) |
                    ((Message.sender_id == uid) & (Message.receiver_id == user_id))
                ).order_by(Message.created_at.desc()).first()
                
                unread_count = Message.query.filter_by(sender_id=uid, receiver_id=user_id, is_read=False).count()
                
                conversations.append({
                    'user_id': uid,
                    'username': user.username,
                    'user_instrument': user.instrument,
                    'last_message': last_message.content if last_message else '',
                    'last_message_time': last_message.created_at.strftime('%Y-%m-%d %H:%M') if last_message else '',
                    'unread_count': unread_count
                })
        
        return jsonify({
            'success': True,
            'conversations': conversations
        })
    
    elif request.method == 'POST':
        # ✅ CHANGE #1 MANDATORY: Route-level check for creator-only messaging
        if current_user.user_type != 'creator':
            abort(403)
        
        data = request.get_json() if request.is_json else request.form.to_dict()
        receiver_id = data.get('receiver_id')
        content = data.get('content')
        
        if not receiver_id or not content:
            return jsonify({'success': False, 'message': 'Receiver ID and content are required'}), 400
        
        # ✅ CHANGE #1 MANDATORY: Receiver must be a creator
        receiver = User.query.get(receiver_id)
        if not receiver or receiver.user_type != 'creator':
            abort(403)
        
        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            content=content
        )
        
        db.session.add(message)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Message sent!',
            'message_id': message.id
        })


@app.route('/api/messages/<int:user_id>', methods=['GET', 'OPTIONS'])
@login_required
def get_messages_with_user(user_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    # ✅ CHANGE #1 MANDATORY: Both users must be creators
    other_user = User.query.get(user_id)
    if not other_user or other_user.user_type != 'creator' or current_user.user_type != 'creator':
        abort(403)
    
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.created_at.asc()).all()
    
    # Mark messages as read
    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.is_read:
            msg.is_read = True
    
    db.session.commit()
    
    messages_data = []
    for msg in messages:
        messages_data.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'receiver_id': msg.receiver_id,
            'content': msg.content,
            'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M'),
            'is_read': msg.is_read,
            'is_own': msg.sender_id == current_user.id
        })
    
    return jsonify({
        'success': True,
        'messages': messages_data,
        'other_user': other_user.to_dict()
    })


# -------------------------------
# USERS API (WITH FILTERS)
# -------------------------------
@app.route('/api/users', methods=['GET', 'OPTIONS'])
def get_users():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    instrument = request.args.get('instrument', '')
    location = request.args.get('location', '')
    user_type = request.args.get('user_type', '')  # ✅ ADDED: Filter by user type
    
    query = User.query
    
    if search:
        query = query.filter(User.username.ilike(f'%{search}%') | User.email.ilike(f'%{search}%'))
    
    if instrument:
        query = query.filter(User.instrument.ilike(f'%{instrument}%'))
    
    if location:
        query = query.filter(User.location.ilike(f'%{location}%'))
    
    if user_type:  # ✅ ADDED: Filter by user type
        query = query.filter(User.user_type == user_type)
    
    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    users_data = [user.to_dict() for user in users.items]
    
    return jsonify({
        'success': True,
        'users': users_data,
        'total': users.total,
        'pages': users.pages,
        'current_page': users.page
    })


@app.route('/api/users/creators', methods=['GET', 'OPTIONS'])  # ✅ ADDED: Get only creators
def get_creators():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    instrument = request.args.get('instrument', '')
    location = request.args.get('location', '')
    
    query = User.query.filter_by(user_type='creator')
    
    if search:
        query = query.filter(User.username.ilike(f'%{search}%') | User.email.ilike(f'%{search}%'))
    
    if instrument:
        query = query.filter(User.instrument.ilike(f'%{instrument}%'))
    
    if location:
        query = query.filter(User.location.ilike(f'%{location}%'))
    
    users = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    users_data = [user.to_dict() for user in users.items]
    
    return jsonify({
        'success': True,
        'users': users_data,
        'total': users.total,
        'pages': users.pages,
        'current_page': users.page
    })


@app.route('/api/users/<int:user_id>', methods=['GET', 'OPTIONS'])
def get_user(user_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    user = User.query.get_or_404(user_id)
    return jsonify({'success': True, 'user': user.to_dict()})


@app.route('/api/users/<int:user_id>/follow', methods=['POST', 'OPTIONS'])
@login_required
def follow_user(user_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    if current_user.id == user_id:
        return jsonify({'success': False, 'message': 'Cannot follow yourself'}), 400
    
    user_to_follow = User.query.get_or_404(user_id)
    
    # ✅ CHANGE #5: Cannot follow listeners
    if user_to_follow.user_type != 'creator':
        abort(403)
    
    existing_follow = Follow.query.filter_by(
        follower_id=current_user.id,
        following_id=user_id
    ).first()
    
    if existing_follow:
        db.session.delete(existing_follow)
        followed = False
    else:
        follow = Follow(follower_id=current_user.id, following_id=user_id)
        db.session.add(follow)
        followed = True
    
    db.session.commit()
    
    # Get updated counts
    following_count = Follow.query.filter_by(follower_id=current_user.id).count()
    follower_count = Follow.query.filter_by(following_id=user_id).count()
    
    return jsonify({
        'success': True,
        'followed': followed,
        'following_count': following_count,
        'follower_count': follower_count
    })


@app.route('/api/users/<int:user_id>/posts', methods=['GET', 'OPTIONS'])
def get_user_posts(user_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    posts = Post.query.filter_by(user_id=user_id)\
        .order_by(Post.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    posts_data = [post.to_dict() for post in posts.items]
    
    return jsonify({
        'success': True,
        'posts': posts_data,
        'total': posts.total,
        'pages': posts.pages
    })


@app.route('/api/users/<int:user_id>/followers', methods=['GET', 'OPTIONS'])
def get_user_followers(user_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    followers = Follow.query.filter_by(following_id=user_id).all()
    followers_data = []
    
    for follow in followers:
        user = User.query.get(follow.follower_id)
        if user:
            followers_data.append(user.to_dict())
    
    return jsonify({
        'success': True,
        'followers': followers_data,
        'count': len(followers_data)
    })


@app.route('/api/users/<int:user_id>/following', methods=['GET', 'OPTIONS'])
def get_user_following(user_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    following = Follow.query.filter_by(follower_id=user_id).all()
    following_data = []
    
    for follow in following:
        user = User.query.get(follow.following_id)
        if user:
            following_data.append(user.to_dict())
    
    return jsonify({
        'success': True,
        'following': following_data,
        'count': len(following_data)
    })


# -------------------------------
# COMMUNITIES API
# -------------------------------
@app.route('/api/communities', methods=['GET', 'POST', 'OPTIONS'])
def communities():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    if request.method == 'GET':
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 12, type=int)
        search = request.args.get('search', '')
        
        query = Community.query
        
        if search:
            query = query.filter(
                Community.name.ilike(f'%{search}%') | 
                Community.description.ilike(f'%{search}%')
            )
        
        communities = query.order_by(Community.member_count.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        communities_data = [community.to_dict() for community in communities.items]
        
        return jsonify({
            'success': True,
            'communities': communities_data,
            'total': communities.total,
            'pages': communities.pages,
            'current_page': communities.page
        })
    
    elif request.method == 'POST':
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        # ✅ CHECK: Only creators can create communities
        if current_user.user_type != 'creator':
            abort(403)
        
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
            
        name = data.get('name')
        description = data.get('description', '')
        icon = data.get('icon', 'users')
        
        if not name:
            return jsonify({'success': False, 'message': 'Community name is required'}), 400
        
        if Community.query.filter_by(name=name).first():
            return jsonify({'success': False, 'message': 'Community name already exists'}), 400
        
        community = Community(
            name=name,
            description=description,
            icon=icon,
            created_by=current_user.id
        )
        
        db.session.add(community)
        db.session.commit()
        
        # Creator automatically becomes primary member
        member = CommunityMember(
            user_id=current_user.id,
            community_id=community.id,
            status='primary',
            approved_at=datetime.utcnow(),
            approved_by=current_user.id
        )
        db.session.add(member)
if member.status in ['primary', 'secondary'] and member.approved_at is None:
    community.member_count += 1
db.session.commit()
        
        return jsonify({'success': True, 'message': 'Community created!', 'community': community.to_dict()})


@app.route('/api/communities/<int:community_id>', methods=['GET', 'OPTIONS'])
def get_community(community_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    community = Community.query.get_or_404(community_id)
    community_data = community.to_dict()
    
    # Add membership status for current user
    if current_user.is_authenticated:
        membership = CommunityMember.query.filter_by(
            user_id=current_user.id,
            community_id=community_id
        ).first()
        
        if membership:
            community_data['user_status'] = membership.status
            community_data['membership_id'] = membership.id
        else:
            community_data['user_status'] = None
            community_data['membership_id'] = None
    
    return jsonify({'success': True, 'community': community_data})


@app.route('/api/communities/<int:community_id>/members', methods=['GET', 'OPTIONS'])
def get_community_members(community_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    status = request.args.get('status', '')
    community = Community.query.get_or_404(community_id)
    
    query = CommunityMember.query.filter_by(community_id=community_id)
    
    if status:
        query = query.filter_by(status=status)
    
    members = query.order_by(CommunityMember.requested_at.desc()).all()
    members_data = [member.to_dict() for member in members]
    
    return jsonify({
        'success': True,
        'members': members_data,
        'total': len(members_data)
    })


@app.route('/api/communities/<int:community_id>/join', methods=['POST', 'OPTIONS'])
@login_required
def join_community(community_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    community = Community.query.get_or_404(community_id)
    
    # Check if already a member
    existing_member = CommunityMember.query.filter_by(
        user_id=current_user.id,
        community_id=community_id
    ).first()
    
    if existing_member:
        if existing_member.status == 'rejected':
            # Allow re-application if previously rejected
            existing_member.status = 'pending'
            existing_member.requested_at = datetime.utcnow()
            existing_member.approved_at = None
            existing_member.approved_by = None
            
            # Create notification for admin
            notification = CommunityRequestNotification(
                community_id=community_id,
                user_id=current_user.id,
                admin_id=community.created_by,
                status='pending'
            )
            db.session.add(notification)
            
            db.session.commit()
            return jsonify({
                'success': True,
                'message': 'Join request sent to admin',
                'status': 'pending'
            })
        else:
            return jsonify({
                'success': False,
                'message': f'You already have {existing_member.status} status in this community'
            }), 400
    
    # Create membership request
    member = CommunityMember(
        user_id=current_user.id,
        community_id=community_id,
        status='pending'
    )
    db.session.add(member)
    
    # Create notification for admin
    notification = CommunityRequestNotification(
        community_id=community_id,
        user_id=current_user.id,
        admin_id=community.created_by,
        status='pending'
    )
    db.session.add(notification)
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Join request sent to admin',
        'status': 'pending'
    })


@app.route('/api/communities/<int:community_id>/members/<int:member_id>/approve', methods=['POST', 'OPTIONS'])
@login_required
def approve_member(community_id, member_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    community = Community.query.get_or_404(community_id)
    member = CommunityMember.query.get_or_404(member_id)
    
    # Check if current user is the admin or creator of community
    if current_user.id != community.created_by:
        return jsonify({'success': False, 'message': 'Only community admin can approve members'}), 403
    
    data = request.get_json() if request.is_json else request.form.to_dict()
    status = data.get('status', 'secondary')  # secondary or primary
    
    if status not in ['secondary', 'primary']:
        return jsonify({'success': False, 'message': 'Invalid status'}), 400
    
    # Update member status
    member.status = status
    member.approved_at = datetime.utcnow()
    member.approved_by = current_user.id
    
    # Update notification
    notification = CommunityRequestNotification.query.filter_by(
        community_id=community_id,
        user_id=member.user_id,
        admin_id=current_user.id
    ).first()
    
    if notification:
        notification.status = 'approved'
    
    # Update community member count (⚠️ Note: Could increment twice if approved multiple times)
    if member.status in ['primary', 'secondary']:
        community.member_count += 1
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': f'Member approved as {status}',
        'member': member.to_dict()
    })


@app.route('/api/communities/<int:community_id>/members/<int:member_id>/reject', methods=['POST', 'OPTIONS'])
@login_required
def reject_member(community_id, member_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    community = Community.query.get_or_404(community_id)
    member = CommunityMember.query.get_or_404(member_id)
    
    # Check if current user is the admin or creator of community
    if current_user.id != community.created_by:
        return jsonify({'success': False, 'message': 'Only community admin can reject members'}), 403
    
    # Update member status
    member.status = 'rejected'
    member.approved_at = datetime.utcnow()
    member.approved_by = current_user.id
    
    # Update notification
    notification = CommunityRequestNotification.query.filter_by(
        community_id=community_id,
        user_id=member.user_id,
        admin_id=current_user.id
    ).first()
    
    if notification:
        notification.status = 'rejected'
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Member request rejected',
        'member': member.to_dict()
    })


@app.route('/api/communities/<int:community_id>/leave', methods=['POST', 'OPTIONS'])
@login_required
def leave_community(community_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    community = Community.query.get_or_404(community_id)
    member = CommunityMember.query.filter_by(
        user_id=current_user.id,
        community_id=community_id
    ).first()
    
    if not member:
        return jsonify({'success': False, 'message': 'You are not a member of this community'}), 400
    
    # If user is the creator, they cannot leave (must delete community instead)
    if current_user.id == community.created_by:
        return jsonify({'success': False, 'message': 'Community creator cannot leave. Delete community instead.'}), 400
    
    # Reduce member count if member was approved
    if member.status in ['primary', 'secondary']:
        community.member_count -= 1
    
    db.session.delete(member)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'You have left the community'
    })


@app.route('/api/communities/<int:community_id>/posts', methods=['GET', 'OPTIONS'])
def get_community_posts(community_id):
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Only get posts specifically for this community
    posts = Post.query.filter_by(community_id=community_id)\
        .order_by(Post.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    posts_data = [post.to_dict() for post in posts.items]
    
    return jsonify({
        'success': True,
        'posts': posts_data,
        'total': posts.total,
        'pages': posts.pages
    })


# -------------------------------
# NOTIFICATIONS API
# -------------------------------
@app.route('/api/notifications', methods=['GET', 'OPTIONS'])
@login_required
def get_notifications():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    # Get community requests for communities where user is admin
    admin_communities = Community.query.filter_by(created_by=current_user.id).all()
    community_ids = [c.id for c in admin_communities]
    
    notifications = []
    
    if community_ids:
        requests = CommunityRequestNotification.query.filter(
            CommunityRequestNotification.community_id.in_(community_ids),
            CommunityRequestNotification.status == 'pending'
        ).order_by(CommunityRequestNotification.created_at.desc()).all()
        
        for req in requests:
            # Optimized: Use get instead of query.get
            user = db.session.get(User, req.user_id)
            community = db.session.get(Community, req.community_id)
            
            notifications.append({
                'id': req.id,
                'type': 'community_request',
                'community_id': req.community_id,
                'community_name': community.name if community else 'Unknown',
                'user_id': req.user_id,
                'username': user.username if user else 'Unknown',
                'user_instrument': user.instrument if user else '',
                'message': f'{user.username if user else "User"} wants to join {community.name if community else "community"}',
                'created_at': req.created_at.strftime('%Y-%m-%d %H:%M'),
                'time_ago': get_time_ago(req.created_at),
                'status': req.status
            })
    
    return jsonify({
        'success': True,
        'notifications': notifications,
        'count': len(notifications)
    })


def get_time_ago(dt):
    now = datetime.utcnow()
    diff = now - dt
    if diff.days > 0:
        return f'{diff.days}d ago'
    if diff.seconds > 3600:
        return f'{diff.seconds // 3600}h ago'
    if diff.seconds > 60:
        return f'{diff.seconds // 60}m ago'
    return 'Just now'


# -------------------------------
# FEED API (SHOW ALL CREATORS)
# -------------------------------
@app.route('/api/feed', methods=['GET', 'OPTIONS'])
@login_required
def get_feed():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # ✅ CHANGE #6: Show posts from ALL creators only
    posts = Post.query.join(User).filter(User.user_type == 'creator')\
        .order_by(Post.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    posts_data = [post.to_dict() for post in posts.items]
    
    return jsonify({
        'success': True,
        'posts': posts_data,
        'total': posts.total,
        'pages': posts.pages
    })


# -------------------------------
# SEARCH API (UNIFIED)
# -------------------------------
@app.route('/api/search', methods=['GET', 'OPTIONS'])
def search():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    query = request.args.get('q', '')
    type_filter = request.args.get('type', 'all')
    instrument = request.args.get('instrument', '')
    location = request.args.get('location', '')
    
    if not query and not instrument and not location:
        return jsonify({'success': False, 'message': 'Search criteria required'}), 400
    
    results = {}
    
    if type_filter in ['all', 'users']:
        # ✅ CHANGE #7: Search creators only
        user_query = User.query.filter(User.user_type == 'creator')
        
        if query:
            user_query = user_query.filter(
                User.username.ilike(f'%{query}%') |
                User.email.ilike(f'%{query}%') |
                User.instrument.ilike(f'%{query}%')
            )
        
        if instrument:
            user_query = user_query.filter(User.instrument.ilike(f'%{instrument}%'))
        
        if location:
            user_query = user_query.filter(User.location.ilike(f'%{location}%'))
        
        users = user_query.limit(20).all()
        results['users'] = [user.to_dict() for user in users]
    
    if type_filter in ['all', 'posts']:
        post_query = Post.query
        
        if query:
            post_query = post_query.filter(
                Post.title.ilike(f'%{query}%') |
                Post.content.ilike(f'%{query}%')
            )
        
        posts = post_query.limit(20).all()
        results['posts'] = [post.to_dict() for post in posts]
    
    if type_filter in ['all', 'communities']:
        community_query = Community.query
        
        if query:
            community_query = community_query.filter(
                Community.name.ilike(f'%{query}%') |
                Community.description.ilike(f'%{query}%')
            )
        
        communities = community_query.limit(10).all()
        results['communities'] = [community.to_dict() for community in communities]
    
    return jsonify({'success': True, 'results': results})


# -------------------------------
# ✅ RUN SERVER
# -------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

from flask import Flask, render_template, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import uuid
from werkzeug.utils import secure_filename
import socket
from sqlalchemy import Enum
import cloudinary
import cloudinary.uploader

app = Flask(__name__)

# CONFIG
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY',
    'musicianhub-secret-key-2024'
)

# ✅ PostgreSQL DATABASE CONFIG
db_url = os.environ.get("DATABASE_URL")

if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ✅ FIXED: SESSION_COOKIE_SECURE - Only enable on Render production
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get("RENDER") == "true"

# ✅ FIXED: Reduce max file size to 100MB (safer for server)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp3', 'wav', 'mp4', 'mov'}

# ✅ Cloudinary configuration
cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
    api_key=os.environ.get("CLOUDINARY_API_KEY"),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET")
)

db = SQLAlchemy(app)
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

# ✅ FIXED: CORS headers middleware - Allow credentials with specific origins
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
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    instrument = db.Column(db.String(100), default='')
    bio = db.Column(db.Text, default='')
    location = db.Column(db.String(100), default='')
    profile_picture = db.Column(db.String(200), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True)
    
    # FIXED: Simplified follow relationships
    # Users that this user is following (people I follow)
    following_users = db.relationship(
        'Follow',
        foreign_keys='Follow.follower_id',
        backref='follower_user',
        lazy='dynamic'
    )
    
    # Users that are following this user (my followers)
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    community_id = db.Column(db.Integer, db.ForeignKey('community.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    likes = db.Column(db.Integer, default=0)
    shares = db.Column(db.Integer, default=0)
    
    # Relationships
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        # ✅ OPTIMIZED: Use get instead of query.get inside loops
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        # ✅ OPTIMIZED: Use get instead of query.get
        user = db.session.get(User, self.user_id)
        return {
            'id': self.id,
            'content': self.content,
            'user_id': self.user_id,
            'username': user.username if user else 'Unknown',
            'user_instrument': user.instrument if user else '',
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


class Community(db.Model):
    __tablename__ = 'community'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50), default='users')
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    member_count = db.Column(db.Integer, default=0)
    
    # Relationships
    posts = db.relationship('Post', backref='community', lazy=True)
    members = db.relationship('CommunityMember', backref='community', lazy=True)
    
    def to_dict(self):
        # ✅ OPTIMIZED: Use get instead of query.get
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
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    community_id = db.Column(db.Integer, db.ForeignKey('community.id'), nullable=False)
    
    # ✅ FIXED: Use String instead of Enum for better PostgreSQL compatibility
    status = db.Column(db.String(20), default='pending')  # 'pending', 'secondary', 'primary', 'rejected'
    
    requested_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Relationships with explicit foreign_keys
    user = db.relationship('User', foreign_keys=[user_id])
    approver = db.relationship('User', foreign_keys=[approved_by])
    
    # Ensure one membership per user per community
    __table_args__ = (db.UniqueConstraint('user_id', 'community_id', name='unique_membership'),)

    def to_dict(self):
        # ✅ OPTIMIZED: Use get instead of query.get
        user = db.session.get(User, self.user_id)
        approver = db.session.get(User, self.approved_by) if self.approved_by else None
        return {
            'id': self.id,
            'user_id': self.user_id,
            'community_id': self.community_id,
            'username': user.username if user else 'Unknown',
            'user_instrument': user.instrument if user else '',
            'status': self.status,
            'requested_at': self.requested_at.strftime('%Y-%m-%d %H:%M'),
            'approved_at': self.approved_at.strftime('%Y-%m-%d %H:%M') if self.approved_at else None,
            'approved_by': self.approved_by,
            'approver_name': approver.username if approver else None
        }


class Follow(db.Model):
    __tablename__ = 'follow'
    
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    following_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # FIXED: Use back_populates instead of backref to avoid naming conflicts
    follower = db.relationship('User', foreign_keys=[follower_id])
    following = db.relationship('User', foreign_keys=[following_id])
    
    # Ensure unique follow relationship
    __table_args__ = (db.UniqueConstraint('follower_id', 'following_id', name='unique_follow'),)


class PostLike(db.Model):
    __tablename__ = 'post_like'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure unique like per user per post
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_like'),)


class PostShare(db.Model):
    __tablename__ = 'post_share'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure unique share per user per post
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_share'),)


class CommunityRequestNotification(db.Model):
    __tablename__ = 'community_request_notification'
    
    id = db.Column(db.Integer, primary_key=True)
    community_id = db.Column(db.Integer, db.ForeignKey('community.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # ✅ FIXED: Use String instead of Enum
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


# ✅ ENSURE DB TABLES CREATE SAFELY
with app.app_context():
    try:
        db.create_all()
        print("✓ Database tables created successfully")
    except Exception as e:
        print(f"✗ Error creating database tables: {e}")
        # Try to continue anyway - tables might already exist


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
        
        if not all([username, email, password]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        user = User(username=username, email=email, instrument=instrument)
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
# POSTS API
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
        
        # ✅ Cloudinary upload logic
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
# USERS API
# -------------------------------
@app.route('/api/users', methods=['GET', 'OPTIONS'])
def get_users():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    instrument = request.args.get('instrument', '')
    
    query = User.query
    
    if search:
        query = query.filter(User.username.ilike(f'%{search}%') | User.email.ilike(f'%{search}%'))
    
    if instrument:
        query = query.filter(User.instrument.ilike(f'%{instrument}%'))
    
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
            query = query.filter(Community.name.ilike(f'%{search}%') | Community.description.ilike(f'%{search}%'))
        
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
    
    # Update community member count
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
            # ✅ OPTIMIZED: Use get instead of query.get
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
# FEED API
# -------------------------------
@app.route('/api/feed', methods=['GET', 'OPTIONS'])
@login_required
def get_feed():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Get posts from users that current user follows
    following_records = Follow.query.filter_by(follower_id=current_user.id).all()
    following_ids = [f.following_id for f in following_records]
    following_ids.append(current_user.id)  # Include own posts
    
    posts = Post.query.filter(Post.user_id.in_(following_ids))\
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
# SEARCH API
# -------------------------------
@app.route('/api/search', methods=['GET', 'OPTIONS'])
def search():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    query = request.args.get('q', '')
    type_filter = request.args.get('type', 'all')
    
    if not query:
        return jsonify({'success': False, 'message': 'Search query is required'}), 400
    
    results = {}
    
    if type_filter in ['all', 'users']:
        users = User.query.filter(
            User.username.ilike(f'%{query}%') |
            User.email.ilike(f'%{query}%') |
            User.instrument.ilike(f'%{query}%')
        ).limit(10).all()
        results['users'] = [user.to_dict() for user in users]
    
    if type_filter in ['all', 'posts']:
        posts = Post.query.filter(
            Post.title.ilike(f'%{query}%') |
            Post.content.ilike(f'%{query}%')
        ).limit(10).all()
        results['posts'] = [post.to_dict() for post in posts]
    
    if type_filter in ['all', 'communities']:
        communities = Community.query.filter(
            Community.name.ilike(f'%{query}%') |
            Community.description.ilike(f'%{query}%')
        ).limit(10).all()
        results['communities'] = [community.to_dict() for community in communities]
    
    return jsonify({'success': True, 'results': results})


# -------------------------------
# RUN SERVER
# -------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

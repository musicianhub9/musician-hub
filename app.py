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
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    instrument = db.Column(db.String(100), default='')
    bio = db.Column(db.Text, default='')
    location = db.Column(db.String(100), default='')
    profile_picture = db.Column(db.String(200), default='')
    user_type = db.Column(db.String(20), default='creator')
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
    
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def to_dict(self):
        # Listeners have no followers
        if self.user_type == 'creator':
            follower_count = Follow.query.filter_by(following_id=self.id).count()
        else:
            follower_count = 0
            
        following_count = Follow.query.filter_by(follower_id=self.id).count()
        
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'instrument': self.instrument,
            'bio': self.bio,
            'location': self.location,
            'profile_picture': self.profile_picture,
            'user_type': self.user_type,
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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    likes = db.Column(db.Integer, default=0)
    shares = db.Column(db.Integer, default=0)
    
    # Relationships
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        user = db.session.get(User, self.user_id)
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
            'user_type': user.user_type if user else 'creator',
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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        user = db.session.get(User, self.user_id)
        return {
            'id': self.id,
            'content': self.content,
            'user_id': self.user_id,
            'username': user.username if user else 'Unknown',
            'user_instrument': user.instrument if user else '',
            'user_type': user.user_type if user else 'creator',
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


class Message(db.Model):
    __tablename__ = 'message'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)


class Follow(db.Model):
    __tablename__ = 'follow'
    
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    following_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Use back_populates instead of backref to avoid naming conflicts
    follower = db.relationship('User', foreign_keys=[follower_id])
    following = db.relationship('User', foreign_keys=[following_id])
    
    # Ensure unique follow relationship
    __table_args__ = (db.UniqueConstraint('follower_id', 'following_id', name='unique_follow'),)


class PostLike(db.Model):
    __tablename__ = 'post_like'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure unique like per user per post
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_like'),)


class PostShare(db.Model):
    __tablename__ = 'post_share'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Ensure unique share per user per post
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_share'),)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# Create tables
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

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nAllow: /", 200, {'Content-Type': 'text/plain'}


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
        user_type = data.get('user_type', 'listener')
        instrument = data.get('instrument', '') if user_type == 'creator' else ''
        
        if not all([username, email, password]):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        if user_type not in ['creator', 'listener']:
            return jsonify({'success': False, 'message': 'Invalid user type'}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        user = User(username=username, email=email, instrument=instrument, user_type=user_type)
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
        
        # Only creators can update instrument
        if 'instrument' in data and user.user_type == 'creator':
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
        
        query = Post.query
        if user_id:
            query = query.filter_by(user_id=user_id)
        
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
        
        # Only creators can post
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
        
        if not title or not content:
            return jsonify({'success': False, 'message': 'Title and content are required'}), 400
        
        post = Post(
            title=title,
            content=content,
            post_type=request.form.get('post_type', 'text'),
            media_url=media_url,
            media_type=media_type,
            user_id=current_user.id
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
    
    # Delete associated likes, shares, and comments
    PostLike.query.filter_by(post_id=post_id).delete()
    PostShare.query.filter_by(post_id=post_id).delete()
    Comment.query.filter_by(post_id=post_id).delete()
    
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
        data = request.get_json() if request.is_json else request.form.to_dict()
        receiver_id = data.get('receiver_id')
        content = data.get('content')
        
        if not receiver_id or not content:
            return jsonify({'success': False, 'message': 'Receiver ID and content are required'}), 400
        
        # Receiver must be a creator
        receiver = User.query.get(receiver_id)
        if not receiver or receiver.user_type != 'creator':
            abort(403)
        
        # Creators can only message creators they follow
        if current_user.user_type == 'creator':
            is_following = Follow.query.filter_by(
                follower_id=current_user.id,
                following_id=receiver_id
            ).first()

            if not is_following:
                return jsonify({
                    'success': False, 
                    'message': 'You must follow this creator to message them'
                }), 403
        
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
    
    # Both users must be creators
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
    user_type = request.args.get('user_type', '')
    
    query = User.query
    
    if search:
        query = query.filter(User.username.ilike(f'%{search}%') | User.email.ilike(f'%{search}%'))
    
    if instrument:
        query = query.filter(User.instrument.ilike(f'%{instrument}%'))
    
    if location:
        query = query.filter(User.location.ilike(f'%{location}%'))
    
    if user_type:
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


@app.route('/api/users/creators', methods=['GET', 'OPTIONS'])
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
    
    # Cannot follow listeners
    if user_to_follow.user_type != 'creator':
        return jsonify({'success': False, 'message': 'You can only follow creators'}), 400
    
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
    follower_count = Follow.query.filter_by(following_id=user_id).count() if user_to_follow.user_type == 'creator' else 0
    
    return jsonify({
        'success': True,
        'followed': followed,
        'following_count': following_count,
        'follower_count': follower_count
    })


@app.route('/api/users/<int:user_id>/following/check/<int:target_id>', methods=['GET', 'OPTIONS'])
@login_required
def check_following(user_id, target_id):
    """Check if user follows target - helper for frontend button state"""
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    follow = Follow.query.filter_by(
        follower_id=user_id,
        following_id=target_id
    ).first()
    
    return jsonify({
        'success': True,
        'is_following': follow is not None
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
    
    user = User.query.get_or_404(user_id)
    # Listeners have no followers
    if user.user_type != 'creator':
        return jsonify({
            'success': True,
            'followers': [],
            'count': 0
        })
    
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
# FEED API (SHOW ALL CREATORS)
# -------------------------------
@app.route('/api/feed', methods=['GET', 'OPTIONS'])
@login_required
def get_feed():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Show posts from ALL creators only
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
# SEARCH API (UNIFIED WITH PRIORITY)
# -------------------------------
@app.route('/api/search', methods=['GET', 'OPTIONS'])
def search():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    query = request.args.get('q', '')
    type_filter = request.args.get('type', 'all')
    instrument = request.args.get('instrument', '')
    location = request.args.get('location', '')
    
    results = {}
    
    # Priority search (starts-with first)
    if type_filter in ['all', 'users']:
        # Search creators only
        user_query = User.query.filter(User.user_type == 'creator')
        
        if query:
            # Get all users that match the query
            all_users = user_query.filter(
                User.username.ilike(f'%{query}%') |
                User.email.ilike(f'%{query}%') |
                User.instrument.ilike(f'%{query}%')
            ).all()
        else:
            all_users = user_query.all()
        
        if instrument:
            all_users = [u for u in all_users if instrument.lower() in u.instrument.lower()]
        
        if location:
            all_users = [u for u in all_users if location.lower() in (u.location or '').lower()]
        
        # Priority sorting: starts-with first
        starts_with = []
        contains = []
        
        for user in all_users:
            if query and user.username.lower().startswith(query.lower()):
                starts_with.append(user)
            else:
                contains.append(user)
        
        # Combine with priority
        priority_users = starts_with + contains
        results['users'] = [user.to_dict() for user in priority_users[:20]]
    
    if type_filter in ['all', 'posts']:
        post_query = Post.query.join(User).filter(User.user_type == 'creator')
        
        if query:
            # Get all posts that match the query
            all_posts = post_query.filter(
                Post.title.ilike(f'%{query}%') |
                Post.content.ilike(f'%{query}%')
            ).all()
        else:
            all_posts = post_query.all()
        
        # Priority sorting for posts
        starts_with = []
        contains = []
        
        for post in all_posts:
            if query and post.title.lower().startswith(query.lower()):
                starts_with.append(post)
            else:
                contains.append(post)
        
        priority_posts = starts_with + contains
        results['posts'] = [post.to_dict() for post in priority_posts[:20]]
    
    return jsonify({'success': True, 'results': results})


# -------------------------------
# ✅ RUN SERVER
# -------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

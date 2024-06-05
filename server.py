

# Made by @c4gwn
# License: MIT
# 19.05.2024



from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy import desc, func, text
from sqlalchemy.orm import joinedload, relationship
from sqlalchemy.ext.hybrid import hybrid_property
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///forum.db' # SQL Database dosyası
app.config['SECRET_KEY'] = 'madebyc4gwnwithluv' # Şifreleme anahtarı
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Bildirim
app.config['UPLOAD_FOLDER'] = 'uploads' # Kullanıcı dosyaları
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024 # Maksimum dosya boyutu
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'bat', 'py'}  # İzin verilen dosya türleri
app.config['ADMIN_USERS'] = ['imrealadminykyk', 'youknowpyro']  # Admin kullanıcı adları

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'



# Kullanıcı verilerini oku
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True) # Kullanıcı kimlik numarası 
    username = db.Column(db.String(80), unique=True, nullable=False) # Kullanıcı adı
    email = db.Column(db.String(120), unique=True, nullable=False) # E-Posta adresi
    password_hash = db.Column(db.String(128)) # Şifrelenmiş giriş parolası
    avatar_path = db.Column(db.String(255), nullable=True) # Kullanıcının profil fotoğrafı konumu (Sunucuda depolanan)
    bio = db.Column(db.Text, nullable=True) # Kullanıcının biyografi metni
    posts = db.relationship('Post', backref='author', lazy=True) # Kullanıcının paylaşımları
    messages_sent = db.relationship('Message', backref='sender', foreign_keys='Message.sender_id', lazy=True) # Kullanıcın gönderdiği mesajlar
    messages_received = db.relationship('Message', backref='recipient', foreign_keys='Message.recipient_id', lazy=True) # Kullanıcının aldığı mesajlar
    favorite_topics = db.relationship('FavoriteTopic', backref='user', lazy=True, cascade="all, delete-orphan") # Kullanıcının favorilediği konular
    notifications = db.relationship('Notification', backref='user', lazy=True, cascade="all, delete-orphan") # Kullanıcnın aldığı tüm bildirimler
    signature = db.Column(db.Text, nullable=True)  # Kullanıcı imzası
# Şifre güvenliği için şifre SHA256 ilşe şifrelenir
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @hybrid_property
    def post_count(self):
        return db.session.query(func.count(Post.id)).filter_by(user_id=self.id).scalar()

    def __repr__(self):
        return f'<User {self.username}>'


class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    posts = db.relationship('Post', backref='topic', lazy=True, cascade="all, delete-orphan")
    last_activity = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())
    favorites = db.relationship('FavoriteTopic', backref='topic', lazy=True)

    @hybrid_property
    def post_count(self):
        return db.session.query(func.count(Post.id)).filter_by(topic_id=self.id).scalar()

    def __repr__(self):
        return f'<Topic {self.title}>'


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True) # Gönderi kimlik numarası
    content = db.Column(db.Text, nullable=False) # Gönderi içeriği
    created_at = db.Column(db.DateTime, default=db.func.now()) # Oluşturulma tarihi
    topic_id = db.Column(db.Integer, db.ForeignKey('topic.id'), nullable=False) # Konu kimliği
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Konu sahibi
    parent_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True) # Konu ailesi
    children = db.relationship('Post', backref=db.backref('parent', remote_side=[id]), lazy=True, cascade="all, delete-orphan") # Alt mesajlar
    edited_at = db.Column(db.DateTime, nullable=True) # Düzenleme tarihi
    reports = db.relationship('Report', backref='post', lazy=True) # Konunun şikayet edilme durumu

    def __repr__(self):
        return f'<Post {self.content[:20]}>'

# Mesajlaşma modeli
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    is_read = db.Column(db.Boolean, default=False)
    reports = db.relationship('Report', backref='message', lazy=True)

    def __repr__(self):
        return f'<Message from {self.sender.username} to {self.recipient.username}>'

# Favori Konular
class FavoriteTopic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    topic_id = db.Column(db.Integer, db.ForeignKey('topic.id'), nullable=False)

    def __repr__(self):
        return f'<FavoriteTopic for {self.topic.title} by {self.user.username}>'

# Şikayetler
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=True)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    reason = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    def __repr__(self):
        return f'<Report for {self.post.content[:20]} by {self.user.username}>'

# Bildirimler
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    def __repr__(self):
        return f'<Notification for {self.user.username}: {self.message}>'

# --- Fonksiyonlar ---

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Bir kullanıcıyı bahsetme
def mention_user(post_content, mentioned_user_id):
    # Bahsedilen kullanıcıya bildirim gönder
    mentioned_user = User.query.get_or_404(mentioned_user_id)
    notification_message = f'{current_user.username} sizi bir gönderide bahsetti: {post_content[:50]}...'
    new_notification = Notification(user=mentioned_user, message=notification_message)
    db.session.add(new_notification)
    db.session.commit()

# --- Veritabanını Başlat ---
with app.app_context():
    db.create_all()

# --- Login Yöneticisi ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Rota Tanımları ---

# Ana Sayfa
@app.route('/')
def index():
    topics = Topic.query.order_by(desc(Topic.last_activity)).all()
    return render_template('index.html', topics=topics, current_user=current_user)

# Başlık Sayfası
@app.route('/topic/<int:topic_id>')
def topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    posts = topic.posts.order_by(Post.created_at.asc())
    return render_template('index.html', topic=topic, posts=posts, current_user=current_user)

# Yeni Başlık Oluşturma
@app.route('/new_topic', methods=['GET', 'POST'])
@login_required
def new_topic():
    if request.method == 'POST':
        title = request.form['title']
        new_topic = Topic(title=title)
        db.session.add(new_topic)
        db.session.commit()
        # İlk gönderiyi ekleme
        first_post = Post(content='Konuya ilk gönderiyi ekleyin.', topic_id=new_topic.id, user_id=current_user.id)
        db.session.add(first_post)
        db.session.commit()
        flash('Başlık başarıyla oluşturuldu!', 'success')
        return redirect(url_for('topic', topic_id=new_topic.id))
    return render_template('index.html', current_user=current_user)

# Yeni Gönderi Oluşturma
@app.route('/topic/<int:topic_id>/new_post', methods=['GET', 'POST'])
@login_required
def new_post(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    if request.method == 'POST':
        content = request.form['content']
        # Bahsetme işlevi
        for username in content.split():
            if username.startswith('@'):
                mentioned_user = User.query.filter_by(username=username[1:]).first()
                if mentioned_user:
                    mention_user(content, mentioned_user.id)

        new_post = Post(content=content, topic_id=topic_id, user_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        flash('Gönderi başarıyla oluşturuldu!', 'success')
        return redirect(url_for('topic', topic_id=topic_id))
    return render_template('index.html', topic=topic, current_user=current_user)

# Kullanıcı Kaydı
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Hesap başarıyla oluşturuldu!', 'success')
        return redirect(url_for('login'))
    return render_template('index.html', current_user=current_user)

# Kullanıcı Girişi
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Başarıyla giriş yaptınız!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Geçersiz kullanıcı adı veya parola!', 'danger')
    return render_template('index.html', current_user=current_user)

# Kullanıcı Çıkışı
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız!', 'success')
    return redirect(url_for('index'))

# Kullanıcı Profili
@app.route('/profile/<int:user_id>')
def profile(user_id):
    user = User.query.get_or_404(user_id)
    posts = user.posts.order_by(desc(Post.created_at))
    favorite_topics = user.favorite_topics.all()
    notifications = user.notifications.order_by(desc(Notification.created_at)).all()
    return render_template('index.html', user=user, posts=posts, favorite_topics=favorite_topics, notifications=notifications, current_user=current_user)

# Kullanıcı Profilini Düzenleme
@app.route('/profile/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_profile(user_id):
    if current_user.id != user_id:
        flash('Bu profili düzenleme yetkiniz yok.', 'danger')
        return redirect(url_for('profile', user_id=user_id))

    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        user.bio = request.form['bio']
        user.signature = request.form.get('signature')  # İmza ekleme
        db.session.commit()
        flash('Profil başarıyla güncellendi!', 'success')
        return redirect(url_for('profile', user_id=user_id))
    return render_template('index.html', user=user, current_user=current_user)

# Gönderi Düzenleme
@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash('Bu gönderiyi düzenleme yetkiniz yok.', 'danger')
        return redirect(url_for('topic', topic_id=post.topic_id))
    if request.method == 'POST':
        post.content = request.form['content']
        post.edited_at = datetime.now()
        db.session.commit()
        flash('Gönderi başarıyla düzenlendi!', 'success')
        return redirect(url_for('topic', topic_id=post.topic_id))
    return render_template('index.html', post=post, current_user=current_user)

# Gönderi Silme
@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash('Bu gönderiyi silme yetkiniz yok.', 'danger')
        return redirect(url_for('topic', topic_id=post.topic_id))
    topic_id = post.topic_id
    db.session.delete(post)
    db.session.commit()
    flash('Gönderi başarıyla silindi!', 'success')
    return redirect(url_for('topic', topic_id=topic_id))

# Başlık Silme
@app.route('/topic/<int:topic_id>/delete', methods=['POST'])
@login_required
def delete_topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    if topic.posts:
        flash('Bu başlıkta gönderi olduğu için silinemiyor.', 'danger')
        return redirect(url_for('topic', topic_id=topic_id))
    db.session.delete(topic)
    db.session.commit()
    flash('Başlık başarıyla silindi!', 'success')
    return redirect(url_for('index'))

# Arama İşlevi
@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        query = request.form['query']
        posts = Post.query.filter(Post.content.like(f'%{query}%')).all()
        return render_template('index.html', query=query, posts=posts, current_user=current_user)
    return render_template('index.html', current_user=current_user)

# Belirli bir kullanıcının oluşturduğu gönderileri listeleme
@app.route('/user/<int:user_id>/posts')
def user_posts(user_id):
    user = User.query.get_or_404(user_id)
    posts = user.posts.order_by(desc(Post.created_at)).all()
    return render_template('index.html', user=user, posts=posts, current_user=current_user)

# En aktif kullanıcıları listeleme
@app.route('/most_active_users')
def most_active_users():
    active_users = User.query.order_by(desc(User.post_count)).limit(10)
    return render_template('index.html', active_users=active_users, current_user=current_user)

# En aktif başlıkları listeleme
@app.route('/most_active_topics')
def most_active_topics():
    active_topics = Topic.query.order_by(desc(Topic.post_count)).limit(10)
    return render_template('index.html', active_topics=active_topics, current_user=current_user)

# Başlıktaki en son gönderi
@app.route('/topic/<int:topic_id>/last_post')
def topic_last_post(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    last_post = topic.posts.order_by(desc(Post.created_at)).first()
    return render_template('index.html', topic=topic, last_post=last_post, current_user=current_user)

# Yorum ekleme
@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    comment = request.form.get('comment')
    if comment:
        new_comment = Post(content=comment, topic_id=post.topic_id, user_id=current_user.id, parent_id=post.id)
        db.session.add(new_comment)
        db.session.commit()
        flash('Yorum başarıyla eklendi!', 'success')
    return redirect(url_for('topic', topic_id=post.topic_id))

# Yorumları gösterme
@app.route('/post/<int:post_id>/comments')
def show_comments(post_id):
    post = Post.query.get_or_404(post_id)
    comments = post.children.order_by(Post.created_at.asc())
    return render_template('index.html', post=post, comments=comments, current_user=current_user)

# Yanıt ekleme
@app.route('/post/<int:post_id>/reply', methods=['POST'])
@login_required
def add_reply(post_id):
    post = Post.query.get_or_404(post_id)
    reply = request.form.get('reply')
    if reply:
        new_reply = Post(content=reply, topic_id=post.topic_id, user_id=current_user.id, parent_id=post.parent_id)
        db.session.add(new_reply)
        db.session.commit()
        flash('Yanıt başarıyla eklendi!', 'success')
    return redirect(url_for('topic', topic_id=post.topic_id))

# Mesaj gönderme
@app.route('/send_message/<int:recipient_id>', methods=['POST'])
@login_required
def send_message(recipient_id):
    recipient = User.query.get_or_404(recipient_id)
    content = request.form.get('message')
    if content:
        new_message = Message(sender=current_user, recipient=recipient, content=content)
        db.session.add(new_message)
        db.session.commit()
        flash('Mesaj başarıyla gönderildi!', 'success')
    return redirect(url_for('profile', user_id=recipient_id))

# Gelen kutusu
@app.route('/inbox')
@login_required
def inbox():
    messages = current_user.messages_received.order_by(desc(Message.created_at)).filter_by(is_read=False)
    read_messages = current_user.messages_received.order_by(desc(Message.created_at)).filter_by(is_read=True)
    return render_template('index.html', messages=messages, read_messages=read_messages, current_user=current_user)

# Mesaj okuma
@app.route('/message/<int:message_id>')
@login_required
def read_message(message_id):
    message = Message.query.get_or_404(message_id)
    if message.recipient_id == current_user.id:
        message.is_read = True
        db.session.commit()
    return render_template('index.html', message=message, current_user=current_user)

# Çıkış kutusu
@app.route('/outbox')
@login_required
def outbox():
    messages = current_user.messages_sent.order_by(desc(Message.created_at))
    return render_template('index.html', messages=messages, current_user=current_user)

# Kullanıcı avatarını yükleme
@app.route('/user/<int:user_id>/upload_avatar', methods=['POST'])
@login_required
def upload_avatar(user_id):
    if current_user.id != user_id:
        flash('Bu kullanıcının avatarını yükleyebilmeniz için yetkiniz yok.', 'danger')
        return redirect(url_for('profile', user_id=user_id))

    if 'avatar' in request.files:
        avatar = request.files['avatar']
        if avatar.filename != '' and allowed_file(avatar.filename):
            avatar.save(os.path.join(app.config['UPLOAD_FOLDER'], avatar.filename))
            current_user.avatar_path = os.path.join('uploads', avatar.filename)
            db.session.commit()
            flash('Avatar başarıyla yüklendi!', 'success')
        else:
            flash('Geçersiz dosya.', 'danger')
    return redirect(url_for('profile', user_id=user_id))

# Kullanıcı avatarını gösterme
@app.route('/user/<int:user_id>/avatar')
def get_avatar(user_id):
    user = User.query.get_or_404(user_id)
    if user.avatar_path:
        return send_from_directory(app.config['UPLOAD_FOLDER'], user.avatar_path)
    else:
        return send_from_directory(os.path.join(app.root_path, 'static'), 'default_avatar.png')

# --- Favori Konular ---

# Bir konuyu favoriye ekleme
@app.route('/topic/<int:topic_id>/favorite', methods=['POST'])
@login_required
def add_favorite_topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    favorite = FavoriteTopic.query.filter_by(user_id=current_user.id, topic_id=topic_id).first()
    if not favorite:
        new_favorite = FavoriteTopic(user_id=current_user.id, topic_id=topic_id)
        db.session.add(new_favorite)
        db.session.commit()
        flash('Başlık favorilere eklendi!', 'success')
    else:
        flash('Başlık zaten favorilerinizde.', 'info')
    return redirect(url_for('topic', topic_id=topic_id))

# Bir konuyu favorilerden çıkarma
@app.route('/topic/<int:topic_id>/remove_favorite', methods=['POST'])
@login_required
def remove_favorite_topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    favorite = FavoriteTopic.query.filter_by(user_id=current_user.id, topic_id=topic_id).first()
    if favorite:
        db.session.delete(favorite)
        db.session.commit()
        flash('Başlık favorilerden çıkarıldı.', 'success')
    else:
        flash('Başlık favorilerinizde değil.', 'info')
    return redirect(url_for('topic', topic_id=topic_id))

# --- Şikayetler ---

# Bir gönderiyi veya mesajı şikayet etme
@app.route('/report/<int:post_id>/<int:message_id>', methods=['POST'])
@login_required
def report(post_id, message_id):
    reason = request.form.get('reason')
    if reason:
        if post_id:
            post = Post.query.get_or_404(post_id)
            new_report = Report(user_id=current_user.id, post_id=post_id, reason=reason)
        elif message_id:
            message = Message.query.get_or_404(message_id)
            new_report = Report(user_id=current_user.id, message_id=message_id, reason=reason)
        else:
            flash('Geçersiz şikayet.', 'danger')
            return redirect(url_for('index'))

        db.session.add(new_report)
        db.session.commit()
        flash('Şikayetiniz başarıyla gönderildi.', 'success')
    return redirect(url_for('index'))

# --- Admin İşlevleri ---

# Admin Girişi (Geçici, daha sonra daha güvenli bir sistemle değiştirin)
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in app.config['ADMIN_USERS'] and password == 'admin':  # Geçici admin yetkilendirmesi
            session['admin'] = True
            flash('Yönetici girişi yapıldı.', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Geçersiz kullanıcı adı veya parola.', 'danger')
    return render_template('index.html', current_user=current_user)

# Admin Paneli
@app.route('/admin_panel')
@login_required
def admin_panel():
    if 'admin' in session:
        reports = Report.query.all()
        users = User.query.all()
        topics = Topic.query.all()
        posts = Post.query.all()
        messages = Message.query.all()
        return render_template('admin_panel.html', reports=reports, users=users, topics=topics, posts=posts, messages=messages, current_user=current_user)
    else:
        flash('Yönetici yetkiniz yok.', 'danger')
        return redirect(url_for('index'))

# Kullanıcı Banlama
@app.route('/admin/ban_user/<int:user_id>', methods=['POST'])
@login_required
def ban_user(user_id):
    if 'admin' in session:
        user = User.query.get_or_404(user_id)
        user.is_banned = True
        db.session.commit()
        flash(f'{user.username} kullanıcısı yasaklandı.', 'success')
    return redirect(url_for('admin_panel'))

# Kullanıcı Yasaklamasını Kaldırma
@app.route('/admin/unban_user/<int:user_id>', methods=['POST'])
@login_required
def unban_user(user_id):
    if 'admin' in session:
        user = User.query.get_or_404(user_id)
        user.is_banned = False
        db.session.commit()
        flash(f'{user.username} kullanıcısının yasağı kaldırıldı.', 'success')
    return redirect(url_for('admin_panel'))

# Kullanıcıya Uyarı Gönderme
@app.route('/admin/send_warning/<int:user_id>', methods=['POST'])
@login_required
def send_warning(user_id):
    if 'admin' in session:
        user = User.query.get_or_404(user_id)
        warning_message = request.form.get('warning_message')
        if warning_message:
            # Uyarıyı gönder (örn. bir mesaj veya e-posta yoluyla)
            # Burada uyarı mesajı gönderme mantığına yer vermelisiniz
            flash(f'{user.username} kullanıcısına uyarı gönderildi.', 'success')
        else:
            flash('Uyarı mesajı boş.', 'danger')
    return redirect(url_for('admin_panel'))

# Gönderiyi Silme
@app.route('/admin/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post_admin(post_id):
    if 'admin' in session:
        post = Post.query.get_or_404(post_id)
        topic_id = post.topic_id
        db.session.delete(post)
        db.session.commit()
        flash('Gönderi başarıyla silindi.', 'success')
    return redirect(url_for('admin_panel'))

# Konuyu Silme
@app.route('/admin/delete_topic/<int:topic_id>', methods=['POST'])
@login_required
def delete_topic_admin(topic_id):
    if 'admin' in session:
        topic = Topic.query.get_or_404(topic_id)
        db.session.delete(topic)
        db.session.commit()
        flash('Konu başarıyla silindi.', 'success')
    return redirect(url_for('admin_panel'))

# Mesajı Silme
@app.route('/admin/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message_admin(message_id):
    if 'admin' in session:
        message = Message.query.get_or_404(message_id)
        db.session.delete(message)
        db.session.commit()
        flash('Mesaj başarıyla silindi.', 'success')
    return redirect(url_for('admin_panel'))

# Şikayetleri Görüntüleme
@app.route('/admin/reports')
@login_required
def admin_reports():
    if 'admin' in session:
        reports = Report.query.all()
        return render_template('admin_reports.html', reports=reports, current_user=current_user)
    else:
        flash('Yönetici yetkiniz yok.', 'danger')
        return redirect(url_for('index'))

# Şikayeti İşleme
@app.route('/admin/process_report/<int:report_id>', methods=['POST'])
@login_required
def process_report(report_id):
    if 'admin' in session:
        report = Report.query.get_or_404(report_id)
        action = request.form.get('action')

        if action == 'delete_post':
            if report.post:
                db.session.delete(report.post)
                db.session.commit()
                flash('Gönderi başarıyla silindi.', 'success')
        elif action == 'delete_message':
            if report.message:
                db.session.delete(report.message)
                db.session.commit()
                flash('Mesaj başarıyla silindi.', 'success')
        elif action == 'ban_user':
            if report.user:
                report.user.is_banned = True
                db.session.commit()
                flash(f'{report.user.username} kullanıcısı yasaklandı.', 'success')

        db.session.delete(report)
        db.session.commit()
    return redirect(url_for('admin_reports'))

# --- Son Gönderilen Mesajlar ---

@app.route('/recent_posts')
def recent_posts():
    recent_posts = Post.query.order_by(desc(Post.created_at)).limit(10)
    return render_template('index.html', recent_posts=recent_posts, current_user=current_user)

# --- Bildirimleri Gösterme ---

@app.route('/notifications')
@login_required
def notifications():
    unread_notifications = current_user.notifications.filter_by(is_read=False).order_by(desc(Notification.created_at)).all()
    read_notifications = current_user.notifications.filter_by(is_read=True).order_by(desc(Notification.created_at)).all()
    return render_template('index.html', unread_notifications=unread_notifications, read_notifications=read_notifications, current_user=current_user)

# Bildirimi okundu olarak işaretleme
@app.route('/notification/<int:notification_id>/read')
@login_required
def mark_notification_as_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id == current_user.id:
        notification.is_read = True
        db.session.commit()
        flash('Bildirim okundu olarak işaretlendi.', 'success')
    return redirect(url_for('notifications'))

# --- İmza Ekleme ---

@app.route('/post/<int:post_id>/signature', methods=['POST'])
@login_required
def add_signature(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id == current_user.id:
        signature = request.form.get('signature')
        if signature:
            current_user.signature = signature
            db.session.commit()
            flash('İmzanız güncellendi.', 'success')
        return redirect(url_for('profile', user_id=current_user.id))
    return redirect(url_for('index'))



def render_post_with_signature(post):
    """Bir gönderi içeriğine kullanıcı imzasını ekler."""
    user = User.query.get(post.user_id)
    if user.signature:
        return f'{post.content}\n\n---\n{user.signature}'
    else:
        return post.content




@app.context_processor
def inject_user():
    return dict(current_user=current_user)



if __name__ == '__main__':
    app.run(debug=True)

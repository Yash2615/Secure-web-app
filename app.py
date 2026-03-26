from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import jwt
import bleach
import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securevault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True

db = SQLAlchemy(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = bleach.clean(request.form['username'])
        password = request.form['password'].encode('utf-8')
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())
        user = User(username=username, password=hashed.decode('utf-8'))
        try:
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
        except:
            return render_template('register.html', error='Username already exists')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = bleach.clean(request.form['username'])
        password = request.form['password'].encode('utf-8')
        user = User.query.filter_by(username=username).first()
        if user:
            if user.locked_until and datetime.datetime.utcnow() < user.locked_until:
                return render_template('login.html', error='Account locked. Try after 15 minutes.')
            if bcrypt.checkpw(password, user.password.encode('utf-8')):
                user.failed_attempts = 0
                db.session.commit()
                token = jwt.encode({
                    'user_id': user.id,
                    'role': user.role,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                }, app.config['SECRET_KEY'], algorithm='HS256')
                session['token'] = token
                session['username'] = user.username
                return redirect(url_for('dashboard'))
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
                db.session.commit()
                return render_template('login.html', error='Invalid credentials')
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'token' not in session:
        return redirect(url_for('login'))
    try:
        data = jwt.decode(session['token'], app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = data['user_id']
    except:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = bleach.clean(request.form['title'])
        content = bleach.clean(request.form['content'])
        note = Note(user_id=user_id, title=title, content=content)
        db.session.add(note)
        db.session.commit()
    notes = Note.query.filter_by(user_id=user_id).all()
    return render_template('dashboard.html', notes=notes, username=session['username'])

@app.route('/delete/<int:note_id>')
def delete_note(note_id):
    if 'token' not in session:
        return redirect(url_for('login'))
    data = jwt.decode(session['token'], app.config['SECRET_KEY'], algorithms=['HS256'])
    note = Note.query.get_or_404(note_id)
    if note.user_id != data['user_id']:
        return "Unauthorized", 403
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)

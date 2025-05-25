from flask import Flask, request, jsonify, render_template, session, url_for, redirect, flash
from flask_cors import CORS
import sqlite3
import bcrypt
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here'
CORS(app, supports_credentials=True)

DATABASE = 'mailsense.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            is_admin BOOLEAN DEFAULT 0
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY,
            sender_id INTEGER NOT NULL,
            recipient_email TEXT NOT NULL,
            subject TEXT,
            body TEXT,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            opened_at TIMESTAMP NULL,
            is_spam BOOLEAN DEFAULT 0,
            tone TEXT,
            FOREIGN KEY (sender_id) REFERENCES users(id)
        )
    ''')

    admin_email = "admin@mailsense.com"
    admin_pass = bcrypt.hashpw("Admin@123".encode(), bcrypt.gensalt()).decode()
    c.execute('''
        INSERT OR IGNORE INTO users (email, password_hash, is_admin)
        VALUES (?, ?, 1)
    ''', (admin_email, admin_pass))

    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('is_admin'):
            return render_template('admin_dashboard.html')
        else:
            return redirect(url_for('sender_dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {
            'email': request.form.get('email'),
            'password': request.form.get('password')
        }

        if not data or not data.get('email') or not data.get('password'):
            return jsonify({"status": "fail", "message": "Missing or invalid data"}), 400

        email = data['email']
        password = data['password']

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT id, password_hash, is_admin FROM users WHERE email = ?', (email,))
        row = c.fetchone()
        conn.close()

        if row and verify_password(password, row[1]):
            session['user_id'] = row[0]
            session['is_admin'] = bool(row[2])
            session['email'] = email
            app.logger.info('%s logged in successfully', email)

            return jsonify({
                'status': 'success',
                'redirect': '/admin_dashboard' if row[2] else '/sender_dashboard'
            })

        app.logger.warning('Failed login attempt for %s', email)
        return jsonify({'status': 'fail', 'message': 'Invalid email or password'}), 401

    return render_template('login.html')

@app.route('/send', methods=['POST'])
def send_email():
    data = request.json
    conn = get_db()
    cur = conn.cursor()

    tone = "na"
    is_spam = 1 if 'lottery' in data['body'].lower() else 0

    cur.execute("""
        INSERT INTO emails (sender_id, recipient_email, subject, body, tone, sent_at, is_spam)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (data['sender_id'], data['recipient'], data['subject'], data['body'], tone, datetime.now(), is_spam))

    conn.commit()
    conn.close()
    return jsonify({'message': 'Email sent', 'is_spam': bool(is_spam)}), 200

@app.route('/emails', methods=['GET'])
def get_sent_emails():
    sender_id = request.args.get('sender_id')
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM emails WHERE sender_id = ? ORDER BY sent_at DESC", (sender_id,))
    emails = [dict(row) for row in cur.fetchall()]
    return jsonify(emails)

@app.route('/inbox', methods=['GET'])
def get_inbox():
    recipient_email = request.args.get('recipient_email')
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT e.*, u.email AS sender_email
        FROM emails e
        JOIN users u ON e.sender_id = u.id
        WHERE e.recipient_email = ?
        ORDER BY e.sent_at DESC
    """, (recipient_email,))
    emails = [dict(row) for row in cur.fetchall()]
    return jsonify(emails)

@app.route('/email/<int:email_id>/open', methods=['POST'])
def mark_email_opened(email_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE emails SET opened_at = ? WHERE id = ?", (datetime.now(), email_id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'message': 'Email marked as read'})

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('You must be logged in as an admin to view this page', 'error')
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT id, email, is_active, is_admin FROM users ORDER BY email')
    users = c.fetchall()

    stats = {
        "active_users": c.execute('SELECT COUNT(*) FROM users WHERE is_active = 1').fetchone()[0],
        "total_emails": c.execute('SELECT COUNT(*) FROM emails').fetchone()[0],
        "spam_emails": c.execute('SELECT COUNT(*) FROM emails WHERE is_spam = 1').fetchone()[0],
        "read_emails": c.execute('SELECT COUNT(*) FROM emails WHERE opened_at IS NOT NULL').fetchone()[0]
    }

    conn.close()
    return render_template('admin_dashboard.html', users=users, stats=stats, current_user=session.get('email'))

@app.route('/sender_dashboard')
def sender_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('sender_dashboard.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            return render_template('register.html', error="Email and password are required")

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return render_template('register.html', error="Invalid email format")

        if len(password) < 6:
            return render_template('register.html', error="Password must be at least 6 characters")

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        if c.fetchone():
            conn.close()
            return render_template('register.html', error="Email already registered")

        hashed_password = hash_password(password)
        c.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', (email, hashed_password))
        conn.commit()
        conn.close()

        return render_template('register.html', message="Registration successful! You can now login.")

    return render_template('register.html')

@app.route('/received_emails')
def received_emails():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_email = session.get('email')

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT e.subject, e.body, e.sent_at, e.opened_at, u.email AS sender_email
        FROM emails e
        JOIN users u ON e.sender_id = u.id
        WHERE e.recipient_email = ?
        ORDER BY e.sent_at DESC
    """, (current_email,))
    emails = cur.fetchall()
    conn.close()

    return render_template('received_emails.html', emails=emails, current_user=current_email)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

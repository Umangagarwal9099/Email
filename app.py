from flask import Flask, request, jsonify, render_template, session, url_for, redirect, flash
from flask_cors import CORS
import sqlite3
import bcrypt
import re
from datetime import datetime
from backend.llama_utils import generate_llama_response , classify_email_tone , detect_spam


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
            return jsonify({
                'status': 'success',
                'redirect': '/admin_dashboard' if row[2] else '/sender_dashboard'
            })

        return jsonify({'status': 'fail', 'message': 'Invalid email or password'}), 401

    return render_template('login.html')

@app.route('/send', methods=['POST'])
def send_email():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401

    data = request.json

    # Validate required keys
    required_keys = ['sender_id', 'recipient', 'subject', 'body']
    missing_keys = [key for key in required_keys if key not in data]
    if missing_keys:
        return jsonify({
            'status': 'error',
            'message': f"Missing required fields: {', '.join(missing_keys)}"
        }), 400

    conn = get_db()
    cur = conn.cursor()

    # Check if user is active
    cur.execute('SELECT is_active FROM users WHERE id = ?', (data['sender_id'],))
    user = cur.fetchone()
    if not user or not user['is_active']:
        conn.close()
        return jsonify({'status': 'error', 'message': 'User account is disabled'}), 403

    body_text = data['body']
    tone = classify_email_tone(body_text)
    is_spam = 1 if detect_spam(body_text) else 0

    cur.execute("""
        INSERT INTO emails (sender_id, recipient_email, subject, body, tone, sent_at, is_spam)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        data['sender_id'],
        data['recipient'],
        data['subject'],
        data['body'],
        tone,
        datetime.now(),
        is_spam
    ))

    conn.commit()
    conn.close()
    return jsonify({'message': 'Email sent', 'is_spam': bool(is_spam)}), 200


@app.route('/sent_emails', methods=['GET'])
def get_user_sent_emails():
    sender_id = request.args.get('sender_id')
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            e.id,
            e.recipient_email,
            e.subject,
            e.body,
            e.sent_at,
            e.opened_at,
            e.is_spam,
            e.tone
        FROM emails e
        WHERE e.sender_id = ?
        ORDER BY e.sent_at DESC
    """, (sender_id,))
    
    emails = []
    for row in cur.fetchall():
        email = dict(row)
        # Convert datetime objects to strings
        if email['sent_at']:
            email['sent_at'] = email['sent_at']
        if email['opened_at']:
            email['opened_at'] = email['opened_at']

        emails.append(email)
    
    conn.close()
    return jsonify(emails)

@app.route('/received_emails')
def received_emails():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_email = session.get('email')

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT 
            e.id, 
            e.subject, 
            e.body, 
            e.sent_at, 
            e.opened_at, 
            u.email AS sender_email
        FROM emails e
        JOIN users u ON e.sender_id = u.id
        WHERE e.recipient_email = ?
        ORDER BY e.sent_at DESC
    """, (current_email,))
    emails = cur.fetchall()
    conn.close()

    return render_template('received_emails.html', emails=emails, current_user=current_email)

@app.route('/mark_email_read/<int:email_id>', methods=['POST'])
def mark_email_read(email_id):
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401
    
    current_email = session.get('email')
    current_time = datetime.now()
    
    conn = get_db()
    cur = conn.cursor()
    
    # Check if email exists and is addressed to current user
    cur.execute("""
        SELECT id FROM emails 
        WHERE id = ? AND recipient_email = ?
    """, (email_id, current_email))
    
    email = cur.fetchone()
    
    if not email:
        conn.close()
        return jsonify({'status': 'error', 'message': 'Email not found or not authorized'}), 404
    
    # Update opened_at if not already set
    cur.execute("""
        UPDATE emails 
        SET opened_at = ?
        WHERE id = ? AND opened_at IS NULL
    """, (current_time, email_id))
    
    conn.commit()
    
    # Get updated email data
    cur.execute("""
        SELECT e.opened_at, u.email AS sender_email, e.tone, e.is_spam
        FROM emails e
        JOIN users u ON e.sender_id = u.id
        WHERE e.id = ?
    """, (email_id,))

    row = cur.fetchone()
    updated_email = dict(row)
    conn.close()

    return jsonify({
        'status': 'success',
        'message': 'Email marked as read',
        'opened_at': updated_email['opened_at'],
        'sender_email': updated_email['sender_email'],
        'tone': updated_email['tone'],
        'is_spam': updated_email['is_spam']
})


@app.route('/sender_dashboard')
def sender_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    current_email = session.get('email')
    user_id = session.get('user_id')

    conn = get_db()
    cur = conn.cursor()

    # Get emails sent by this user with proper formatting
    cur.execute("""
        SELECT 
            e.id,
            e.recipient_email,
            e.subject,
            e.body,
            strftime('%Y-%m-%d %H:%M', e.sent_at) as sent_at,
            CASE WHEN e.opened_at IS NULL THEN NULL 
                 ELSE strftime('%Y-%m-%d %H:%M', e.opened_at) END as opened_at,
            e.is_spam,
            e.tone
        FROM emails e
        WHERE e.sender_id = ?
        ORDER BY e.sent_at DESC
    """, (user_id,))

    sent_emails = cur.fetchall()
    conn.close()

    return render_template('sender_dashboard.html', 
                         current_user=current_email, 
                         current_id=user_id, 
                         emails=sent_emails)
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        flash('You must be logged in as an admin to view this page', 'error')
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT id, email, is_active, is_admin FROM users ORDER BY email')
    users = c.fetchall()

    # Get all emails with sender information
    c.execute('''
        SELECT e.*, u.email as sender_email 
        FROM emails e
        JOIN users u ON e.sender_id = u.id
        ORDER BY e.sent_at DESC
    ''')
    all_emails = [dict(zip([column[0] for column in c.description], row)) for row in c.fetchall()]

    stats = {
        "active_users": c.execute('SELECT COUNT(*) FROM users WHERE is_active = 1').fetchone()[0],
        "total_emails": c.execute('SELECT COUNT(*) FROM emails').fetchone()[0],
        "spam_emails": c.execute('SELECT COUNT(*) FROM emails WHERE is_spam = 1').fetchone()[0],
        "read_emails": c.execute('SELECT COUNT(*) FROM emails WHERE opened_at IS NOT NULL').fetchone()[0]
    }

    conn.close()
    return render_template('admin_dashboard.html', users=users, stats=stats, all_emails=all_emails, current_user=session.get('email'))
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

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    if 'user_id' not in session or not session.get('is_admin'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # First delete all emails associated with this user
        cur.execute("DELETE FROM emails WHERE sender_id = ?", (user_id,))
        
        # Then delete the user
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        conn.commit()
        return jsonify({'status': 'success', 'message': 'User permanently removed'})
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        conn.close()

        
@app.route('/llama_generate_tone', methods=['POST'])
def llama_generate_tone():
    
    text = request.json.get('text', '')
    result = classify_email_tone(text)
    raw = generate_llama_response(f"Email: {text}\nAnswer:", max_tokens=10)
    return jsonify({'tone': result, 'raw': raw})


@app.route('/llama_generate_spam', methods=['POST'])
def llama_generate_spam():
    
    text = request.json.get('text', '')
    result = detect_spam(text)
    raw = generate_llama_response(f"Email: {text}\nAnswer:", max_tokens=5)
    return jsonify({'spam': result, 'raw': raw})



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True,use_reloader=False)

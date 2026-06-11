import sqlite3
import os
import random
import string
import traceback
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from threading import Lock
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError

load_dotenv()

app = Flask(__name__)

# ---------- Безопасность ----------
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
    print("⚠️ ВНИМАНИЕ: SECRET_KEY не задан. Сгенерирован временный ключ.")

# ---------- Защита от brute force ----------
failed_attempts = defaultdict(list)
blocked_ips = {}
_lock = Lock()

def is_ip_blocked(ip):
    with _lock:
        if ip in blocked_ips and datetime.now() < blocked_ips[ip]:
            return True
        elif ip in blocked_ips:
            del blocked_ips[ip]
        return False

def register_failed_attempt(ip):
    with _lock:
        now = datetime.now()
        failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < timedelta(minutes=10)]
        failed_attempts[ip].append(now)
        if len(failed_attempts[ip]) >= 10:
            blocked_ips[ip] = now + timedelta(minutes=10)
            return True
        return False

# ---------- Flask-Limiter ----------
app.config['RATELIMIT_STORAGE_URI'] = 'memory://'
app.config['RATELIMIT_STRATEGY'] = 'fixed-window'
app.config['RATELIMIT_HEADERS_ENABLED'] = True

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
)
limiter.init_app(app)

# ---------- CSRF ----------
csrf = CSRFProtect(app)

@app.context_processor
def inject_csrf_token():
    return {'csrf_token': generate_csrf()}

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Ошибка безопасности. Пожалуйста, обновите страницу и попробуйте снова.', 'danger')
    return redirect(request.referrer or url_for('index'))

@app.errorhandler(429)
def ratelimit_handler(e):
    flash(f"⚠️ Слишком много запросов. {e.description}", 'danger')
    return redirect(request.url)

# ---------- Google OAuth ----------
app.config['GOOGLE_CLIENT_ID'] = os.environ.get('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get('GOOGLE_CLIENT_SECRET')
if not app.config['GOOGLE_CLIENT_ID'] or not app.config['GOOGLE_CLIENT_SECRET']:
    print("⚠️ ВНИМАНИЕ: Не заданы GOOGLE_CLIENT_ID и GOOGLE_CLIENT_SECRET. Вход через Google не будет работать.")

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# ---------- База данных (постоянный том /data) ----------
DATABASE = '/data/database.db'
# Убедимся, что папка /data существует (на Timeweb она будет создана при монтировании тома)
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ---------- Вспомогательные функции ----------
def get_active_reservation_for_book(book_id):
    conn = get_db_connection()
    res = conn.execute('SELECT * FROM reservations WHERE book_id = ? AND status = "active"', (book_id,)).fetchone()
    conn.close()
    return res

def count_active_reservations_for_user(user_id):
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) as cnt FROM reservations WHERE user_id = ? AND status = "active"', (user_id,)).fetchone()['cnt']
    conn.close()
    return count

def generate_pickup_code():
    chars = [c for c in (string.ascii_uppercase + string.digits) if c not in 'O0I1']
    while True:
        code = ''.join(random.choices(chars, k=6))
        conn = get_db_connection()
        existing = conn.execute('SELECT id FROM reservations WHERE pickup_code = ? AND status = "active"', (code,)).fetchone()
        conn.close()
        if not existing:
            return code

MAX_ACTIVE_RESERVATIONS = 3

def init_db():
    """Инициализация БД — создаёт таблицы и начальные данные."""
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     username TEXT UNIQUE, 
                     password TEXT, 
                     is_admin INTEGER DEFAULT 0,
                     email TEXT UNIQUE)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS books 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     title TEXT, 
                     author TEXT, 
                     price REAL, 
                     img TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS orders 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     user_id INTEGER, 
                     date TEXT, 
                     total REAL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS order_items 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     order_id INTEGER, 
                     book_title TEXT, 
                     price REAL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS reservations 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     user_id INTEGER,
                     book_id INTEGER,
                     book_title TEXT,
                     book_author TEXT,
                     book_price REAL,
                     status TEXT DEFAULT 'active',
                     created_at TEXT,
                     pickup_code TEXT,
                     FOREIGN KEY (user_id) REFERENCES users (id),
                     FOREIGN KEY (book_id) REFERENCES books (id))''')
    
    # Добавляем колонку email, если её нет
    columns = conn.execute("PRAGMA table_info(users)").fetchall()
    has_email = any(col['name'] == 'email' for col in columns)
    if not has_email:
        conn.execute('ALTER TABLE users ADD COLUMN email TEXT UNIQUE')
        conn.execute("UPDATE users SET email = username || '@localhost' WHERE email IS NULL")
    else:
        conn.execute("UPDATE users SET email = username || '@localhost' WHERE email IS NULL")
    
    admin = conn.execute('SELECT * FROM users WHERE username = "admin"').fetchone()
    if not admin:
        admin_password = os.environ.get('ADMIN_PASSWORD')
        if not admin_password:
            admin_password = secrets.token_urlsafe(12)
            print(f"\n*** Администратор создан со случайным паролем: {admin_password} ***")
        conn.execute('INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
                     ('admin', 'admin@localhost', generate_password_hash(admin_password), 1))
        conn.commit()
    
    if conn.execute('SELECT COUNT(*) FROM books').fetchone()[0] == 0:
        sample_books = [
            ('Мастер и Маргарита', 'Михаил Булгаков', 850, 'https://picsum.photos/id/1/200/300'),
            ('1984', 'Джордж Оруэлл', 600, 'https://picsum.photos/id/2/200/300'),
            ('Ведьмак. Последнее желание', 'Анджей Сапковский', 950, 'https://picsum.photos/id/3/200/300'),
            ('Три товарища', 'Эрих Мария Ремарк', 720, 'https://picsum.photos/id/4/200/300'),
        ]
        conn.executemany('INSERT INTO books (title, author, price, img) VALUES (?, ?, ?, ?)', sample_books)
        conn.commit()
    conn.close()

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ---------- МАРШРУТЫ ----------
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_auth', _external=True)
    return google.authorize_redirect(redirect_uri)

@csrf.exempt
@app.route('/auth/google')
def google_auth():
    token = google.authorize_access_token()
    resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token)
    if resp.status_code != 200:
        flash('Не удалось получить данные от Google. Попробуйте позже.', 'danger')
        return redirect(url_for('login'))
    user_info = resp.json()
    
    email = user_info['email']
    name = user_info.get('name', email.split('@')[0])
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    if not user:
        try:
            conn.execute('INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
                         (name, email, '', 0))
            conn.commit()
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        except sqlite3.IntegrityError:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['is_admin'] = user['is_admin']
    session['email'] = email
    flash(f'Добро пожаловать, {user["username"]}!', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour", error_message="Слишком много попыток регистрации. Подождите час.")
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password_raw = request.form.get('password', '')
        
        if not username or not email or not password_raw:
            flash('Все поля обязательны для заполнения', 'danger')
            return render_template('register.html')
        
        password = generate_password_hash(password_raw)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                         (username, email, password))
            conn.commit()
            flash('Регистрация успешна! Теперь войдите.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                flash('Пользователь с таким логином уже существует', 'danger')
            elif 'email' in str(e):
                flash('Пользователь с таким email уже зарегистрирован', 'danger')
            else:
                flash('Ошибка при регистрации. Попробуйте другие данные.', 'danger')
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}\n{traceback.format_exc()}")
            flash('Внутренняя ошибка сервера. Попробуйте позже.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per 5 minutes", error_message="Слишком много неудачных попыток. Попробуйте через 5 минут.")
def login():
    ip = request.remote_addr
    if is_ip_blocked(ip):
        flash('⚠️ Слишком много неудачных попыток. Ваш IP заблокирован на 10 минут.', 'danger')
        return render_template('login.html')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and user['password'] and check_password_hash(user['password'], password):
            with _lock:
                if ip in failed_attempts:
                    del failed_attempts[ip]
                if ip in blocked_ips:
                    del blocked_ips[ip]
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            session['email'] = user['email']
            flash(f'Добро пожаловать, {user["username"]}!', 'success')
            return redirect(url_for('index'))
        else:
            blocked = register_failed_attempt(ip)
            if blocked:
                flash('⚠️ Вы временно заблокированы на 10 минут из-за частых неудачных попыток входа.', 'danger')
            else:
                flash('Неверный логин или пароль', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/')
def index():
    search = request.args.get('search', '')
    sort = request.args.get('sort', 'default')
    conn = get_db_connection()
    query = 'SELECT * FROM books WHERE title LIKE ? OR author LIKE ?'
    params = (f'%{search}%', f'%{search}%')
    if sort == 'price_asc':
        query += ' ORDER BY price ASC'
    elif sort == 'price_desc':
        query += ' ORDER BY price DESC'
    elif sort == 'title_asc':
        query += ' ORDER BY title ASC'
    else:
        query += ' ORDER BY id'
    books = conn.execute(query, params).fetchall()
    
    books_list = []
    for book in books:
        reserved = get_active_reservation_for_book(book['id']) is not None
        books_list.append(dict(book, is_reserved=reserved))
    conn.close()
    return render_template('index.html', books=books_list, search=search, current_sort=sort)

@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    conn = get_db_connection()
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        price = request.form['price']
        img = request.form['img']
        conn.execute('INSERT INTO books (title, author, price, img) VALUES (?, ?, ?, ?)',
                     (title, author, price, img))
        conn.commit()
        flash('Книга успешно добавлена!', 'success')
    books = conn.execute('SELECT * FROM books').fetchall()
    conn.close()
    return render_template('admin.html', books=books)

@app.route('/admin/delete/<int:id>')
@admin_required
def delete_book(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM books WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Книга удалена', 'success')
    return redirect(url_for('admin'))

@app.route('/add_to_cart/<int:book_id>')
def add_to_cart(book_id):
    if 'cart' not in session:
        session['cart'] = []
    session['cart'].append(book_id)
    session.modified = True
    flash('Книга добавлена в корзину', 'info')
    return redirect(request.referrer or url_for('index'))

@app.route('/cart')
def cart():
    cart_ids = session.get('cart', [])
    conn = get_db_connection()
    items = []
    for bid in cart_ids:
        book = conn.execute('SELECT * FROM books WHERE id = ?', (bid,)).fetchone()
        if book:
            items.append(book)
    total = sum(item['price'] for item in items)
    conn.close()
    return render_template('cart.html', items=items, total=total)

@app.route('/cart/remove/<int:index>')
def remove_from_cart(index):
    if 'cart' in session and 0 <= index < len(session['cart']):
        session['cart'].pop(index)
        session.modified = True
        flash('Товар удалён из корзины', 'info')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['POST'])
def checkout():
    return redirect(url_for('payment'))

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    cart_ids = session.get('cart', [])
    if not cart_ids:
        return redirect(url_for('index'))
    
    conn = get_db_connection()
    items = []
    for bid in cart_ids:
        book = conn.execute('SELECT * FROM books WHERE id = ?', (bid,)).fetchone()
        if book:
            items.append(book)
    total = sum(item['price'] for item in items)
    conn.close()
    
    if request.method == 'POST':
        conn = get_db_connection()
        user_id = session['user_id']
        total = 0
        items_to_save = []
        for bid in cart_ids:
            book = conn.execute('SELECT * FROM books WHERE id = ?', (bid,)).fetchone()
            if book:
                items_to_save.append(book)
                total += book['price']
        
        cur = conn.cursor()
        cur.execute('INSERT INTO orders (user_id, date, total) VALUES (?, ?, ?)',
                    (user_id, datetime.now().strftime("%d.%m.%Y %H:%M"), total))
        order_id = cur.lastrowid
        for item in items_to_save:
            conn.execute('INSERT INTO order_items (order_id, book_title, price) VALUES (?, ?, ?)',
                         (order_id, item['title'], item['price']))
        conn.commit()
        conn.close()
        
        session['cart'] = []
        flash('Оплата прошла успешно (демо-режим). Заказ оформлен!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('payment.html', items=items, total=total)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user_id = session['user_id']
    orders = conn.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC', (user_id,)).fetchall()
    history = []
    for order in orders:
        items = conn.execute('SELECT * FROM order_items WHERE order_id = ?', (order['id'],)).fetchall()
        history.append({'info': order, 'items': items})
    conn.close()
    return render_template('profile.html', history=history)

@app.route('/rights')
def rights():
    return render_template('rights.html')

@app.route('/reserve/<int:book_id>')
def reserve_book(book_id):
    if 'user_id' not in session:
        flash('Войдите, чтобы бронировать книги', 'warning')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    book = conn.execute('SELECT * FROM books WHERE id = ?', (book_id,)).fetchone()
    if not book:
        conn.close()
        flash('Книга не найдена', 'danger')
        return redirect(url_for('index'))
    
    existing = get_active_reservation_for_book(book_id)
    if existing:
        conn.close()
        flash(f'Книга "{book["title"]}" уже забронирована другим пользователем', 'warning')
        return redirect(url_for('index'))
    
    user_id = session['user_id']
    active_cnt = count_active_reservations_for_user(user_id)
    if active_cnt >= MAX_ACTIVE_RESERVATIONS:
        conn.close()
        flash(f'Вы не можете забронировать более {MAX_ACTIVE_RESERVATIONS} книг одновременно', 'danger')
        return redirect(url_for('index'))
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pickup_code = generate_pickup_code()
    conn.execute(
        'INSERT INTO reservations (user_id, book_id, book_title, book_author, book_price, status, created_at, pickup_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (user_id, book_id, book['title'], book['author'], book['price'], 'active', now, pickup_code)
    )
    conn.commit()
    conn.close()
    
    flash(f'Книга "{book["title"]}" забронирована! Ваш код выдачи: {pickup_code}. Сообщите его на кассе.', 'success')
    return redirect(url_for('my_reservations'))

@app.route('/my_reservations')
def my_reservations():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    reservations = conn.execute(
        'SELECT * FROM reservations WHERE user_id = ? AND status = "active" ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('my_reservations.html', reservations=reservations)

@app.route('/cancel_reservation/<int:reservation_id>')
def cancel_reservation(reservation_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    reservation = conn.execute(
        'SELECT * FROM reservations WHERE id = ? AND user_id = ? AND status = "active"',
        (reservation_id, session['user_id'])
    ).fetchone()
    if not reservation:
        conn.close()
        flash('Бронь не найдена или уже отменена', 'warning')
        return redirect(url_for('my_reservations'))
    conn.execute('UPDATE reservations SET status = "cancelled" WHERE id = ?', (reservation_id,))
    conn.commit()
    conn.close()
    flash('Бронь отменена', 'info')
    return redirect(url_for('my_reservations'))

@app.route('/admin/reservations')
@admin_required
def admin_reservations():
    conn = get_db_connection()
    reservations = conn.execute('''
        SELECT r.*, u.username 
        FROM reservations r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('admin_reservations.html', reservations=reservations)

@app.route('/admin/reservations/delete/<int:reservation_id>')
@admin_required
def admin_delete_reservation(reservation_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM reservations WHERE id = ?', (reservation_id,))
    conn.commit()
    conn.close()
    flash('Бронь удалена', 'success')
    return redirect(url_for('admin_reservations'))

@app.route('/admin/pickup_by_code', methods=['GET', 'POST'])
@admin_required
def admin_pickup_by_code():
    if request.method == 'POST':
        code = request.form.get('code', '').strip().upper()
        conn = get_db_connection()
        reservation = conn.execute(
            'SELECT r.*, u.username FROM reservations r JOIN users u ON r.user_id = u.id WHERE r.pickup_code = ? AND r.status = "active"',
            (code,)
        ).fetchone()
        if reservation:
            conn.execute('UPDATE reservations SET status = "completed" WHERE id = ?', (reservation['id'],))
            conn.commit()
            conn.close()
            flash(f'Книга "{reservation["book_title"]}" выдана пользователю {reservation["username"]}', 'success')
        else:
            conn.close()
            flash('Неверный код или бронь уже неактивна', 'danger')
        return redirect(url_for('admin_pickup_by_code'))
    return render_template('admin_pickup_by_code.html')

# ---------- ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ (только после всех маршрутов) ----------
init_db()
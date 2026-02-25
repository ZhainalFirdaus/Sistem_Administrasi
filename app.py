import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, Response, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
import csv
import io
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import logging
import time
import base64

# Muat konfigurasi dari file .env
load_dotenv()

app = Flask(__name__)

# -------------------------------------------------------
# KEAMANAN: Baca SECRET_KEY dari environment (.env)
# -------------------------------------------------------
_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key or _secret_key == 'ganti-dengan-secret-key-acak-minimal-32-karakter':
    import secrets
    _secret_key = secrets.token_hex(32)
    print("[PERINGATAN KEAMANAN] SECRET_KEY tidak ditemukan di .env! Menggunakan kunci sementara.")
    print("[PERINGATAN KEAMANAN] Isi SECRET_KEY di file .env sebelum deployment!")

app.config['SECRET_KEY'] = _secret_key

# -------------------------------------------------------
# KEAMANAN: Konfigurasi Cookie Sesi yang Aman
# -------------------------------------------------------
# Otomatis aktifkan Secure Cookie di environment production (Railway pakai HTTPS)
_is_production = os.environ.get('RAILWAY_ENVIRONMENT') or os.environ.get('RAILWAY_PROJECT_ID')
app.config['SESSION_COOKIE_SECURE'] = bool(_is_production)
app.config['SESSION_COOKIE_HTTPONLY'] = True   # Cegah akses cookie via JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Proteksi dasar CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # Sesi kadaluarsa setelah 1 jam

# Konfigurasi Database (baca dari .env atau Railway Variable)
# Gunakan strip() untuk mencegah spasi kosong yang tidak sengaja
db_url = os.environ.get('MYSQL_URL', '').strip() or os.environ.get('DATABASE_URL', '').strip()

if db_url and db_url.lower() != 'none':
    # Pastikan formatnya mysql+pymysql:// agar SQLAlchemy bisa jalan
    if db_url.startswith('mysql://'):
        db_url = db_url.replace('mysql://', 'mysql+pymysql://', 1)
    elif not db_url.startswith('mysql+pymysql://'):
        # Jika tidak ada prefix sama sekali, kita asumsikan ini URL mentah
        pass
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
else:
    # Fallback jika URL tidak ada, coba ambil komponen satu per satu
    # Railway sering menyediakan MYSQLHOST, MYSQLUSER, dll secara otomatis
    db_host = os.environ.get('MYSQLHOST') or os.environ.get('DB_HOST', 'localhost')
    db_user = os.environ.get('MYSQLUSER') or os.environ.get('DB_USER', 'root')
    db_password = os.environ.get('MYSQLPASSWORD') or os.environ.get('DB_PASSWORD', '')
    db_name = os.environ.get('MYSQLDATABASE') or os.environ.get('DB_NAME', 'db_administrasi')
    db_port = os.environ.get('MYSQLPORT', '3306')
    
    # Konstruksi manual dengan pymysql driver
    mysql_uri = f'mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
    app.config['SQLALCHEMY_DATABASE_URI'] = mysql_uri

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Konfigurasi Upload
# Gunakan path absolut agar send_from_directory tidak bingung dengan working directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Maksimal 16MB

# Buat folder upload jika belum ada
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Silakan login terlebih dahulu untuk mengakses halaman ini.'
login_manager.login_message_category = 'error'

# -------------------------------------------------------
# KEAMANAN: Rate Limiter (Cegah Brute Force)
# -------------------------------------------------------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],  # Tidak ada limit global — hanya pada route tertentu
    storage_uri="memory://"
)

# -------------------------------------------------------
# KEAMANAN: Logging Error ke File
# -------------------------------------------------------
if not os.path.exists('logs'):
    os.makedirs('logs')
logging.basicConfig(
    filename='logs/app.log',
    level=logging.WARNING,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# -------------------------------------------------------
# KEAMANAN: Fernet Encryption untuk Token Akses File
# -------------------------------------------------------
_fernet_key_str = os.environ.get('FERNET_KEY', '')
try:
    if not _fernet_key_str or 'generate-fernet-key' in _fernet_key_str:
        raise ValueError
    fernet = Fernet(_fernet_key_str.encode())
except (ValueError, Exception):
    # Auto-generate sementara — akan hilang setiap restart!
    _auto_key = Fernet.generate_key()
    fernet = Fernet(_auto_key)
    print("[PERINGATAN KEAMANAN] FERNET_KEY tidak ditemukan di .env! Menggunakan kunci sementara.")
    print("[PERINGATAN KEAMANAN] Generate dengan: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
    print(f"[PERINGATAN KEAMANAN] Lalu isi FERNET_KEY={_auto_key.decode()} di file .env")

def generate_file_token(filename: str, ttl_seconds: int = 300) -> str:
    """Buat token terenkripsi Fernet untuk akses file, berlaku selama ttl_seconds."""
    expire_at = int(time.time()) + ttl_seconds
    payload = f"{expire_at}:{filename}"
    token = fernet.encrypt(payload.encode())
    # URL-safe base64 sudah ditangani Fernet, kembalikan sebagai string
    return base64.urlsafe_b64encode(token).decode()

def verify_file_token(token_str: str) -> str | None:
    """Verifikasi token dan kembalikan nama file jika valid, None jika tidak."""
    try:
        raw = base64.urlsafe_b64decode(token_str.encode())
        payload = fernet.decrypt(raw).decode()
        expire_at_str, filename = payload.split(':', 1)
        if int(time.time()) > int(expire_at_str):
            return None  # Token kadaluarsa
        # Cegah path traversal: pastikan nama file aman
        safe_name = os.path.basename(filename)
        if safe_name != filename or '..' in filename:
            return None
        return safe_name
    except (InvalidToken, ValueError, Exception):
        return None

# ====================
# MODELS
# ====================

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    nrp = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=True) # Opsional sekarang
    email = db.Column(db.String(100), unique=True, nullable=True)    # Opsional sekarang
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('admin', 'user'), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    documents = db.relationship('Document', backref='owner', lazy=True)

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Enum('Pending', 'Revisi', 'Approved', 'Rejected'), default='Pending')
    admin_comment = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # Null untuk broadcast atau jika ditujukan ke admin
    target_role = db.Column(db.Enum('admin', 'user'), nullable=True) # Tambahan untuk mempermudah targeting
    message = db.Column(db.String(255), nullable=False)
    link = db.Column(db.String(255), nullable=True) # URL tujuan saat notifikasi diklik
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            notifications = Notification.query.filter(
                (Notification.target_role == 'admin') | (Notification.user_id == current_user.id)
            ).order_by(Notification.created_at.desc()).limit(10).all()
            unread_count = Notification.query.filter(
                ((Notification.target_role == 'admin') | (Notification.user_id == current_user.id)),
                Notification.is_read == False
            ).count()
        else:
            notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(10).all()
            unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        return dict(notifications=notifications, unread_count=unread_count)
    return dict(notifications=[], unread_count=0)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.context_processor
def inject_file_token_generator():
    """Sediakan helper generate_file_token() di semua template Jinja2."""
    return dict(generate_file_token=generate_file_token)

@app.context_processor
def inject_upload_config():
    """Ekspos konfigurasi upload ke semua template agar selalu sinkron."""
    max_bytes = app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)
    max_mb = max_bytes // (1024 * 1024)
    return dict(max_upload_mb=max_mb)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ====================
# INISIALISASI DATABASE
# Dijalankan saat app pertama kali dimuat (termasuk oleh gunicorn di Railway)
# ====================
def initialize_database():
    """Buat tabel dan admin default jika belum ada."""
    try:
        # 1. Cek URI target (untuk log)
        uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        short_uri = uri.split('@')[-1] if '@' in uri else uri
        print(f"--- [DATABASE INIT] Target: {short_uri} ---", flush=True)
        
        # 2. Sinkronisasi Tabel (CREATE TABLE IF NOT EXISTS)
        db.create_all()
        
        # 3. Buat admin default jika belum ada
        admin_user = User.query.filter_by(nrp='admin').first()
        if not admin_user:
            hashed_password = generate_password_hash('admin123')
            new_admin = User(
                name='Administrator', 
                nrp='admin', 
                password_hash=hashed_password, 
                role='admin'
            )
            db.session.add(new_admin)
            db.session.commit()
            print("✅ Admin default created (NRP: admin, Pass: admin123).", flush=True)
        
        print("✅ Database connection & sync successful.", flush=True)
    except Exception as e:
        # Jangan biarkan aplikasi crash hanya karena DB sedang sirkulasi/restart
        print(f"⚠️ Peringatan inisialisasi database: {e}", flush=True)
        db.session.rollback()

# Flag global untuk melacak apakah DB sudah diinisialisasi
_db_initialized = False

@app.before_request
def before_first_request_func():
    """Jalankan inisialisasi database hanya satu kali saat request pertama datang."""
    global _db_initialized
    if not _db_initialized:
        with app.app_context():
            initialize_database()
        _db_initialized = True



@app.route('/health')
def health_check():
    """Endpoint untuk healthcheck Railway."""
    return {"status": "healthy", "database": "connected"}, 200

@app.route('/')
def index():
    """Halaman utama, redirect ke dashboard jika sudah login."""
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Proses registrasi user baru (default role: user)."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        name = request.form.get('full_name')
        nrp = request.form.get('nrp')
        password = request.form.get('password')
        
        user_exists = User.query.filter_by(nrp=nrp).first()
        
        if user_exists:
            flash('NRP / No. Casis sudah terdaftar.', 'error')
        else:
            try:
                hashed_password = generate_password_hash(password)
                new_user = User(name=name, nrp=nrp, password_hash=hashed_password, role='user')
                db.session.add(new_user)
                db.session.commit()
                flash('Registrasi berhasil! Silakan login.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Terjadi kesalahan saat menyimpan data.', 'error')
                
    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Reset kata sandi khusus user (bukan admin) via verifikasi NRP + Nama."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template('forgot_password.html', step='verify')

    step = request.form.get('step')

    # ---- STEP 1: Verifikasi Identitas ----
    if step == 'verify':
        nrp   = request.form.get('nrp', '').strip()
        name  = request.form.get('name', '').strip()

        user = User.query.filter(
            User.nrp == nrp,
            User.role == 'user'   # Khusus user, bukan admin
        ).first()

        if not user:
            flash('NRP tidak ditemukan atau Anda adalah Admin. Hubungi Administrator.', 'error')
            return render_template('forgot_password.html', step='verify')

        # Bandingkan nama (tidak case-sensitive)
        if user.name.strip().lower() != name.lower():
            flash('Nama lengkap tidak cocok dengan data kami.', 'error')
            return render_template('forgot_password.html', step='verify')

        # Identitas cocok → lanjut ke step 2
        return render_template('forgot_password.html',
                               step='reset',
                               nrp=nrp,
                               verified_name=user.name)

    # ---- STEP 2: Simpan Password Baru ----
    elif step == 'reset':
        nrp            = request.form.get('nrp', '').strip()
        new_password   = request.form.get('new_password', '')
        confirm_pw     = request.form.get('confirm_password', '')

        if len(new_password) < 6:
            flash('Kata sandi minimal 6 karakter.', 'error')
            user = User.query.filter_by(nrp=nrp).first()
            return render_template('forgot_password.html', step='reset',
                                   nrp=nrp, verified_name=user.name if user else '')

        if new_password != confirm_pw:
            flash('Konfirmasi kata sandi tidak cocok.', 'error')
            user = User.query.filter_by(nrp=nrp).first()
            return render_template('forgot_password.html', step='reset',
                                   nrp=nrp, verified_name=user.name if user else '')

        user = User.query.filter(User.nrp == nrp, User.role == 'user').first()
        if not user:
            flash('Data tidak valid. Silakan ulangi proses dari awal.', 'error')
            return redirect(url_for('forgot_password'))

        try:
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            logging.info(f"Password reset berhasil untuk NRP: {nrp}")
            flash('Kata sandi berhasil diperbarui! Silakan login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Gagal reset password: {e}")
            flash('Terjadi kesalahan. Coba lagi.', 'error')
            return redirect(url_for('forgot_password'))

    return redirect(url_for('forgot_password'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", error_message="Terlalu banyak percobaan login. Coba lagi dalam 1 menit.")
def login():
    """Proses login menggunakan session/Flask-Login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        login_id = request.form.get('login_id')
        password = request.form.get('password')
        
        try:
            # Cari user berdasarkan NRP
            user = User.query.filter_by(nrp=login_id).first()
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                if user.role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('user_dashboard'))
            else:
                flash('NRP atau password salah.', 'error')
        except Exception as e:
            flash('Gagal terhubung ke database. Pastikan Laragon menyala.', 'error')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Proses logout user."""
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def user_dashboard():
    """Dashboard User: Menampilkan list dokumen milik user bersangkutan."""
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
        
    documents = Document.query.filter_by(user_id=current_user.id).all()
    
    # Calculate stats
    total_count = len(documents)
    waiting_count = len([d for d in documents if d.status == 'Pending'])
    revision_count = len([d for d in documents if d.status == 'Revisi'])
    
    return render_template('user_dashboard.html', 
                         documents=documents,
                         total_count=total_count,
                         waiting_count=waiting_count,
                         revision_count=revision_count)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """Dashboard Admin: Hanya bisa diakses oleh role admin."""
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini.', 'error')
        return redirect(url_for('user_dashboard'))
        
    search_query = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip()
    
    query = Document.query
    
    if search_query:
        query = query.join(User).filter(
            (Document.file_name.like(f'%{search_query}%')) |
            (User.name.like(f'%{search_query}%')) |
            (User.nrp.like(f'%{search_query}%'))
        )
    
    if status_filter:
        query = query.filter(Document.status == status_filter)
        
    documents = query.order_by(Document.created_at.desc()).all()
    
    # Real-time Statistics
    total_users_count = User.query.filter_by(role='user').count()
    pending_count = Document.query.filter_by(status='Pending').count()
    approved_count = Document.query.filter_by(status='Approved').count()
    
    return render_template('admin_dashboard.html', 
                         documents=documents, 
                         pending_count=pending_count, 
                         approved_count=approved_count, 
                         total_users_count=total_users_count,
                         search_query=search_query,
                         status_filter=status_filter)

@app.route('/admin/export')
@login_required
def export_documents():
    """Export daftar dokumen ke format CSV."""
    if current_user.role != 'admin':
        return redirect(url_for('user_dashboard'))
        
    status_filter = request.args.get('status', '').strip()
    query = Document.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    documents = query.order_by(Document.created_at.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['ID', 'Nama File', 'Pengunggah (NRP)', 'Status', 'Komentar Admin', 'Tanggal Unggah'])
    
    for doc in documents:
        writer.writerow([
            doc.id,
            doc.file_name,
            f"{doc.owner.name} ({doc.owner.nrp})",
            doc.status,
            doc.admin_comment or '-',
            doc.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename=daftar_dokumen_{datetime.now().strftime('%Y%m%d')}.csv"}
    )

@app.route('/admin/reports')
@login_required
def admin_reports():
    """Halaman Laporan dan Statistik untuk Admin."""
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini.', 'error')
        return redirect(url_for('user_dashboard'))
        
    # Statistics
    total_docs = Document.query.count()
    status_counts = {
        'Pending': Document.query.filter_by(status='Pending').count(),
        'Approved': Document.query.filter_by(status='Approved').count(),
        'Revisi': Document.query.filter_by(status='Revisi').count(),
        'Rejected': Document.query.filter_by(status='Rejected').count(),
    }
    
    total_users = User.query.filter_by(role='user').count()
    
    return render_template('admin_reports.html', 
                         total_docs=total_docs,
                         status_counts=status_counts,
                         total_users=total_users)

@app.route('/admin/users')
@login_required
def admin_users():
    """Halaman Manajemen User untuk Admin."""
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini.', 'error')
        return redirect(url_for('user_dashboard'))
        
    page = request.args.get('page', 1, type=int)
    users_pagination = User.query.order_by(User.id.desc()).paginate(page=page, per_page=8, error_out=False)
    return render_template('admin_users.html', users_pagination=users_pagination)

@app.route('/admin/user/create', methods=['POST'])
@login_required
def create_user():
    """Membuat user baru oleh admin."""
    if current_user.role != 'admin':
        flash('Akses ditolak.', 'error')
        return redirect(url_for('user_dashboard'))
        
    name = request.form.get('name')
    nrp = request.form.get('nrp')
    password = request.form.get('password')
    role = request.form.get('role', 'user')
    
    if not nrp or not password:
        flash('NRP dan Password wajib diisi.', 'error')
        return redirect(url_for('admin_users'))
        
    # Cek apakah NRP sudah ada
    existing_user = User.query.filter_by(nrp=nrp).first()
    if existing_user:
        flash(f'User dengan NRP {nrp} sudah terdaftar.', 'error')
        return redirect(url_for('admin_users'))
        
    try:
        hashed_password = generate_password_hash(password)
        new_user = User(name=name, nrp=nrp, password_hash=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash(f'User {name or nrp} berhasil dibuat.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Gagal membuat user baru.', 'error')
        
    return redirect(url_for('admin_users'))

@app.route('/admin/user/edit/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    """Update data user oleh admin."""
    if current_user.role != 'admin':
        flash('Akses ditolak.', 'error')
        return redirect(url_for('user_dashboard'))
        
    user = User.query.get_or_404(user_id)
    new_name = request.form.get('name')
    new_role = request.form.get('role')
    
    if user:
        user.name = new_name
        user.role = new_role
        try:
            db.session.commit()
            flash(f'User {user.nrp} berhasil diperbarui.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Gagal memperbarui user.', 'error')
            
    return redirect(url_for('admin_users'))

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Hapus user oleh admin."""
    if current_user.role != 'admin':
        flash('Akses ditolak.', 'error')
        return redirect(url_for('user_dashboard'))
        
    if user_id == current_user.id:
        flash('Anda tidak dapat menghapus akun Anda sendiri.', 'error')
        return redirect(url_for('admin_users'))
        
    user = User.query.get_or_404(user_id)
    try:
        # Opsional: hapus dokumen terkait jika perlu, atau biarkan foreign key handle (jika ON DELETE CASCADE)
        # Dalam hal ini kita asumsikan dokumen harus dihapus atau di-nullkan
        Document.query.filter_by(user_id=user_id).delete()
        db.session.delete(user)
        db.session.commit()
        flash(f'User {user.nrp} dan dokumen terkait berhasil dihapus.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Gagal menghapus user.', 'error')
        
    return redirect(url_for('admin_users'))

@app.route('/admin/documents')
@login_required
def admin_documents():
    """Halaman Daftar Semua Dokumen untuk Admin dengan Fitur Search."""
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini.', 'error')
        return redirect(url_for('user_dashboard'))
        
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    
    query = Document.query.join(User)
    
    if search_query:
        query = query.filter(
            db.or_(
                Document.file_name.like(f'%{search_query}%'),
                User.name.like(f'%{search_query}%'),
                User.nrp.like(f'%{search_query}%')
            )
        )
    
    documents_pagination = query.order_by(Document.created_at.desc()).paginate(page=page, per_page=8, error_out=False)
    return render_template('admin_documents.html', documents_pagination=documents_pagination, search_query=search_query)

@app.route('/admin/document/<int:doc_id>')
@login_required
def admin_document_review(doc_id):
    """Halaman Review Dokumen Spesifik untuk Admin."""
    if current_user.role != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini.', 'error')
        return redirect(url_for('user_dashboard'))
        
    document = Document.query.get_or_404(doc_id)
    return render_template('admin_document_review.html', document=document)

@app.route('/preview/<token>')
@login_required
def preview_file(token):
    """Serve file dengan token terenkripsi (Fernet). Berlaku 5 menit."""
    filename = verify_file_token(token)
    if not filename:
        abort(403)  # Token tidak valid atau kadaluarsa
    # Pastikan file ini benar-benar milik user atau user adalah admin
    doc = Document.query.filter_by(file_path=filename).first()
    if not doc:
        abort(404)
    if current_user.role != 'admin' and doc.user_id != current_user.id:
        abort(403)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

@app.route('/download/<token>')
@login_required
def download_file(token):
    """Serve file sebagai attachment dengan token terenkripsi (Fernet). Berlaku 5 menit."""
    filename = verify_file_token(token)
    if not filename:
        abort(403)
    doc = Document.query.filter_by(file_path=filename).first()
    if not doc:
        abort(404)
    if current_user.role != 'admin' and doc.user_id != current_user.id:
        abort(403)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/file_token/<int:doc_id>')
@login_required
def get_file_token(doc_id):
    """Generate token akses file untuk dokumen tertentu (redirect ke preview)."""
    doc = Document.query.get_or_404(doc_id)
    if current_user.role != 'admin' and doc.user_id != current_user.id:
        abort(403)
    token = generate_file_token(doc.file_path)
    return redirect(url_for('preview_file', token=token))

@app.route('/admin/update_document', methods=['POST'])
@login_required
def update_document_status():
    """Fungsi untuk admin mengupdate status dan komentar dokumen."""
    if current_user.role != 'admin':
        flash('Akses ditolak.', 'error')
        return redirect(url_for('user_dashboard'))
        
    doc_id = request.form.get('doc_id')
    new_status = request.form.get('status')
    admin_comment = request.form.get('comment')

    if not doc_id or not new_status:
        flash('Data tidak lengkap.', 'error')
        return redirect(url_for('admin_dashboard'))

    document = db.session.get(Document, int(doc_id))
    if document:
        document.status = new_status
        document.admin_comment = admin_comment

        # Tambah Notifikasi untuk User
        msg = f"Dokumen '{document.file_name}' Anda telah diperbarui menjadi '{new_status}'."
        link = url_for('user_dashboard')
        notif = Notification(user_id=document.user_id, message=msg, target_role='user', link=link)
        db.session.add(notif)

        try:
            db.session.commit()
            flash(f'Dokumen {document.file_name} berhasil diperbarui menjadi {new_status}.', 'success')
        except Exception as e:
            db.session.rollback()
            logging.error(f'Gagal update dokumen id={doc_id}: {e}', exc_info=True)
            flash(f'Terjadi kesalahan saat mengupdate dokumen: {str(e)}', 'error')
    else:
        flash('Dokumen tidak ditemukan.', 'error')

    return redirect(url_for('admin_dashboard'))

@app.route('/edit_document/<int:doc_id>', methods=['POST'])
@login_required
def edit_document(doc_id):
    """Memperbarui file pada dokumen yang sudah ada."""
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
        
    document = db.session.get(Document, doc_id) or abort(404)
    
    # Keamanan: Pastikan hanya pemilik yang bisa edit
    if document.user_id != current_user.id:
        flash('Akses ditolak.', 'error')
        return redirect(url_for('user_dashboard'))
        
    if 'document' not in request.files:
        flash('Tidak ada file bagian form.', 'error')
        return redirect(url_for('user_dashboard'))
        
    file = request.files['document']
    if file.filename == '':
        flash('Pilih file terlebih dahulu.', 'error')
        return redirect(url_for('user_dashboard'))
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S_')
        unique_filename = timestamp + filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            # Hapus file lama jika ada
            old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], document.file_path)
            if os.path.exists(old_file_path):
                os.remove(old_file_path)
                
            # Simpan file baru
            file.save(file_path)
            
            # Update data dokumen
            document.file_name = filename
            document.file_path = unique_filename
            document.status = 'Pending' # Reset status
            document.admin_comment = None # Bersihkan komentar lama
            
            # Tambah Notifikasi untuk Admin (Pembaruan)
            msg = f"User {current_user.name} memperbarui dokumen: {filename}"
            link = url_for('admin_document_review', doc_id=document.id)
            notif = Notification(target_role='admin', message=msg, link=link)
            db.session.add(notif)
            
            db.session.commit()
            flash('Dokumen berhasil diperbarui. Menunggu review kembali.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {str(e)}', 'error')
    else:
        flash('Tipe file tidak valid.', 'error')
        
    return redirect(url_for('user_dashboard'))

@app.route('/delete_document/<int:doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    """Menghapus dokumen dari database dan file fisik."""
    document = Document.query.get_or_404(doc_id)
    
    # Keamanan: Admin bisa hapus semua, User hanya bisa hapus miliknya
    if current_user.role != 'admin' and document.user_id != current_user.id:
        flash('Anda tidak memiliki izin untuk menghapus dokumen ini.', 'error')
        return redirect(url_for('user_dashboard'))
    
    try:
        # Hapus file fisik
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], document.file_path)
        if os.path.exists(file_path):
            os.remove(file_path)
            
        # Hapus record database
        db.session.delete(document)
        db.session.commit()
        
        flash(f'Dokumen {document.file_name} berhasil dihapus.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal menghapus dokumen: {str(e)}', 'error')
        
    if current_user.role == 'admin':
        return redirect(url_for('admin_documents'))
    return redirect(url_for('user_dashboard'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_document():
    """Fungsi upload dokumen dari dashboard user."""
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
        
    if 'document' not in request.files:
        flash('Tidak ada file bagian form.', 'error')
        return redirect(url_for('user_dashboard'))
        
    file = request.files['document']
    if file.filename == '':
        flash('Pilih file terlebih dahulu.', 'error')
        return redirect(url_for('user_dashboard'))
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Menambahkan timestamp untuk menghindari nama file bentrok
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S_')
        unique_filename = timestamp + filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            file.save(file_path)
            new_doc = Document(
                user_id=current_user.id,
                file_name=filename,
                file_path=unique_filename,
                status='Pending'
            )
            db.session.add(new_doc)
            db.session.flush() # Agar new_doc.id tersedia untuk url_for di bawah
            
            # Tambah Notifikasi untuk Admin
            msg = f"User {current_user.name} mengunggah dokumen baru: {filename}"
            link = url_for('admin_document_review', doc_id=new_doc.id)
            notif = Notification(target_role='admin', message=msg, link=link)
            db.session.add(notif)
            
            db.session.commit()
            flash('Dokumen berhasil diunggah.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Terjadi kesalahan saat menyimpan file atau data.', 'error')
    else:
        flash('Tipe file tidak valid. Hanya PDF, DOC, DOCX, JPG, PNG.', 'error')
        
    return redirect(url_for('user_dashboard'))

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Halaman pengaturan akun - ganti password."""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Password saat ini salah.', 'error')
        elif new_password != confirm_password:
            flash('Password baru dan konfirmasi tidak cocok.', 'error')
        elif len(new_password) < 6:
            flash('Password baru harus minimal 6 karakter.', 'error')
        else:
            try:
                current_user.password_hash = generate_password_hash(new_password)
                db.session.commit()
                flash('Password berhasil diperbarui. Silakan login ulang.', 'success')
                logout_user()
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Gagal memperbarui password.', 'error')
    
    return render_template('settings.html')

@app.errorhandler(413)
def request_entity_too_large(error):
    flash('Ukuran file terlalu besar. Maksimal 5MB.', 'error')
    return redirect(request.referrer or url_for('user_dashboard')), 413

@app.errorhandler(404)
def page_not_found(error):
    """Halaman 404 yang ramah pengguna."""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    """Tangani error server tanpa menampilkan detail error ke pengguna."""
    db.session.rollback()  # Rollback sesi database jika ada yang menggantung
    logging.error(f"Internal Server Error: {error}", exc_info=True)
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Tangani error rate limit (terlalu banyak request)."""
    flash('Terlalu banyak percobaan. Harap tunggu sebentar sebelum mencoba lagi.', 'error')
    return redirect(url_for('login')), 429


@app.route('/notifications/read', methods=['POST'])
@login_required
def mark_notifications_read():
    """Tandai semua notifikasi user saat ini sebagai terbaca."""
    if current_user.role == 'admin':
        unread = Notification.query.filter(
            ((Notification.target_role == 'admin') | (Notification.user_id == current_user.id)),
            Notification.is_read == False
        ).all()
    else:
        unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    
    for n in unread:
        n.is_read = True
    
    try:
        db.session.commit()
    except:
        db.session.rollback()
        
    return '', 204

if __name__ == '__main__':
    # Pastikan database ada sebelum menjalankan create_all()
    import pymysql
    try:
        conn = pymysql.connect(host='localhost', user='root', password='')
        cursor = conn.cursor()
        cursor.execute('CREATE DATABASE IF NOT EXISTS db_administrasi')
        conn.close()
        print("Database 'db_administrasi' diperiksa/dibuat.")
    except Exception as e:
        print(f"Peringatan: Gagal membuat database otomatis. ({e})")

    with app.app_context():
        try:
            db.create_all()
            print("Tabel berhasil diperiksa/dibuat.")
            
            # Buat akun admin default jika belum ada
            admin_user = User.query.filter_by(nrp='admin').first()
            if not admin_user:
                hashed_password = generate_password_hash('admin123')
                new_admin = User(name='Administrator', nrp='admin', password_hash=hashed_password, role='admin')
                db.session.add(new_admin)
                db.session.commit()
                print("Akun admin default berhasil dibuat! (NRP: admin, Password: admin123)")
                
        except Exception as e:
            print(f"Peringatan: Gagal terhubung ke database. Pastikan MySQL berjalan. ({e})")
    print("\n" + "="*50)
    print("  ✅ Aplikasi berhasil dijalankan!")
    print("  🌐 Akses di: http://127.0.0.1:5000")
    print("  📌 Tekan Ctrl+C untuk menghentikan server")
    print("="*50 + "\n")
    # Gunakan PORT dari environment variable (Railway) atau default 8080 (seperti permintaan user)
    port = int(os.environ.get('PORT', 8080))
    host = '0.0.0.0'
    print(f"🚀 Memulai server di {host}:{port}")
    app.run(host=host, port=port, debug=False)

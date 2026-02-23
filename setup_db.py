"""
setup_db.py — Jalankan SEKALI untuk membuat database dan semua tabel.
Usage: python setup_db.py
"""
import pymysql
import sys
import os

# =============================================
# KONFIGURASI DATABASE
# Sesuaikan jika Anda mengubah password MySQL
# =============================================
DB_HOST     = 'localhost'
DB_USER     = 'root'
DB_PASSWORD = ''           # Kosong jika default Laragon
DB_NAME     = 'db_administrasi'
DB_PORT     = 3306

def create_database():
    print("\n" + "="*55)
    print("  DocAdmin — Setup Database")
    print("="*55)

    # 1. Coba koneksi ke MySQL
    print(f"\n[1] Menghubungkan ke MySQL di {DB_HOST}:{DB_PORT}...")
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            port=DB_PORT
        )
        print("    ✅ Koneksi berhasil!")
    except Exception as e:
        print(f"\n    ❌ GAGAL koneksi ke MySQL!")
        print(f"    Error: {e}")
        print(f"\n    Pastikan Laragon sudah berjalan dan MySQL aktif!")
        sys.exit(1)

    # 2. Buat database
    cursor = conn.cursor()
    print(f"\n[2] Membuat database '{DB_NAME}'...")
    try:
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` "
            f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        conn.commit()
        print(f"    ✅ Database '{DB_NAME}' berhasil dibuat!")
    except Exception as e:
        print(f"    ❌ Gagal membuat database: {e}")
        sys.exit(1)
    finally:
        cursor.close()
        conn.close()

    # 3. Buat semua tabel via Flask app context
    print(f"\n[3] Membuat tabel-tabel...")
    try:
        # Import Flask app
        sys.path.insert(0, os.path.dirname(__file__))
        from app import app, db, User
        from werkzeug.security import generate_password_hash

        with app.app_context():
            db.create_all()
            print("    ✅ Semua tabel berhasil dibuat!")

            # 4. Buat akun admin default
            print(f"\n[4] Membuat akun admin default...")
            admin = User.query.filter_by(nrp='admin').first()
            if not admin:
                hashed_pw = generate_password_hash('admin123')
                new_admin = User(
                    name='Administrator',
                    nrp='admin',
                    password_hash=hashed_pw,
                    role='admin'
                )
                db.session.add(new_admin)
                db.session.commit()
                print("    ✅ Akun admin dibuat!")
                print("       NRP      : admin")
                print("       Password : admin123")
                print("       ⚠️  Segera ganti password setelah login pertama!")
            else:
                print("    ℹ️  Akun admin sudah ada, dilewati.")

    except Exception as e:
        print(f"    ❌ Gagal membuat tabel: {e}")
        sys.exit(1)

    print("\n" + "="*55)
    print("  ✅ Setup selesai! Jalankan: python app.py")
    print("  🌐 Akses: http://127.0.0.1:5000")
    print("="*55 + "\n")

if __name__ == '__main__':
    create_database()

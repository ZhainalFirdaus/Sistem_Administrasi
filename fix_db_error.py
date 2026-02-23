from app import app, db
import sqlalchemy as sa

with app.app_context():
    # Drop table notifications jika sudah ada agar bisa dibuat ulang dengan kolom baru
    try:
        db.session.execute(sa.text("DROP TABLE IF EXISTS notifications"))
        db.session.commit()
        print("Table 'notifications' dropped successfully.")
    except Exception as e:
        print(f"Error dropping table: {e}")
        db.session.rollback()

    # Buat ulang semua tabel yang belum ada atau yang baru di-drop
    db.create_all()
    print("Database tables recreated successfully.")

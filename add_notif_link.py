from app import app, db
from sqlalchemy import text

def add_link_column():
    with app.app_context():
        try:
            # Check if column exists (optional but safe)
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE notifications ADD COLUMN link VARCHAR(255) DEFAULT NULL"))
                conn.commit()
            print("Successfully added 'link' column to 'notifications' table.")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    add_link_column()

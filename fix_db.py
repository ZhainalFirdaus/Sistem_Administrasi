from app import app, db

with app.app_context():
    try:
        print("Dropping all tables...")
        db.drop_all()
        print("Recreating all tables with new schema...")
        db.create_all()
        print("Database schema successfully updated!")
        
        # Re-create default admin
        from app import User, generate_password_hash
        admin_user = User(name='Administrator', nrp='admin', password_hash=generate_password_hash('admin123'), role='admin')
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin created (NRP: admin, Pass: admin123)")
        
    except Exception as e:
        print(f"Error updating database: {e}")

from app import app, db, Document

with app.app_context():
    docs = Document.query.all()
    print("ID | File Name | File Path")
    print("-" * 50)
    for doc in docs:
        print(f"{doc.id} | {doc.file_name} | {doc.file_path}")

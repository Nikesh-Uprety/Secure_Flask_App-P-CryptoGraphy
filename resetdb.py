import os
from app import create_app, db
from app.models import User, Message

app = create_app()

def reset_database():
    with app.app_context():
        try:
            print("Deleting all messages...")
            Message.query.delete()
            print("Deleting all users...")
            User.query.delete()
            db.session.commit()
            print("Database records cleared successfully!")
            
            # Clear uploads folder (adjust path as needed)
            uploads_path = os.path.join('static', 'uploads')
            if os.path.exists(uploads_path):
                print(f"Clearing uploads folder at {uploads_path}...")
                for filename in os.listdir(uploads_path):
                    file_path = os.path.join(uploads_path, filename)
                    try:
                        if os.path.isfile(file_path):
                            os.unlink(file_path)
                        elif os.path.isdir(file_path):
                            for f in os.listdir(file_path):
                                os.unlink(os.path.join(file_path, f))
                            os.rmdir(file_path)
                    except Exception as e:
                        print(f"Error deleting {file_path}: {e}")
                print("Uploads folder cleared!")
            else:
                print("Uploads folder not found, skipping...")
                
            # Verify empty database
            print("\nVerification:")
            print(f"Total users: {User.query.count()}")
            print(f"Total messages: {Message.query.count()}")
            
        except Exception as e:
            db.session.rollback()
            print(f"Error during reset: {str(e)}")

if __name__ == '__main__':
    reset_database()
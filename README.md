# SecureChat

SecureChat is a Flask-based web application for secure messaging and file sharing. It features encrypted text communication, digitally signed file uploads, and a real-time chat interface, ensuring user privacy and data integrity.

## Features

## How It Works

1. **Setup and Installation**:
   - Clone: `git clone https://github.com/Nikesh-Uprety/Secure_Flask_App-P-CryptoGraphy.git`
   - Install dependencies: `pip install -r requirements.txt`.
   - Configure environment variables (e.g., `SECRET_KEY`, `UPLOAD_FOLDER`) in a `.env` file.
   - Initialize the database: `flask db init`, `flask db migrate`, `flask db upgrade`.
   - Run the application: `flask run`.

2. **User Registration and Login**:
   - Users register with a username, email, and password, which are stored securely in a SQLite/MySQL database.
   - Upon login, Flask-Login manages user sessions, restricting access to authenticated users only.

3. **Sending Messages**:
   - Users select a recipient from the list of registered users.
   - Messages are encrypted using the recipient’s public key and signed with the sender’s private key.
   - The encrypted message and signature are stored in the database and decrypted by the recipient using their private key.

4. **File Upload and Sharing**:
   - Users can attach files (e.g., images, PDFs) via the chat form.
   - Files are saved to `app/static/uploads/<user_id>/<filename>` and resized (for images) to a maximum of 800x800 pixels.
   - A digital signature is generated for each file using the sender’s private key and stored in the database.
   - Files are accessible via the `/download/<message_id>` endpoint, with signature verification before serving.

5. **Chat Interface**:
   - The chat view (`/chat/<user_id>`) displays messages and files in real-time, with sender messages styled in blue and receiver messages in white.
   - Images are rendered as clickable previews, while other files appear as downloadable links.
   - JavaScript fetches new messages every 2 seconds, updating the chatbox without page reloads.

6. **Security Measures**:
   - Messages are encrypted to prevent unauthorized access.
   - File and message signatures ensure data integrity and authenticity.
   - File uploads are validated for allowed extensions (PNG, JPG, JPEG, GIF, PDF, DOC, DOCX, TXT) and scanned for correct MIME types.
   - Secure file paths prevent directory traversal attacks.

## How It Works

1. **Installation**:
   - Clone: `git clone https://github.com/Nikesh-Uprety/Secure_Flask_App-P-CryptoGraphy.git`
   - Install: `pip install -r requirements.txt`
   - Set up `.env` with `SECRET_KEY`, `UPLOAD_FOLDER`, etc.
   - Initialize DB: `flask db init`, `flask db migrate`, `flask db upgrade`
   - Run: `flask run` or `python3 run.py`

2. **Usage**:
   - Register and log in at `/register` and `/login`.
   - Select a user from `/index` to chat.
   - Send encrypted messages or signed files (images auto-preview).
   - Files download via secure links with signature verification.

## Project Structure

```
secure_chat_app/
│
├── app/
│   ├── __init__.py
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── forms.py
│   │   ├── routes.py
│   │   └── utils.py
│   ├── chat/
│   │   ├── __init__.py
│   │   ├── forms.py
│   │   ├── routes.py
│   │   └── utils.py
│   ├── models.py
│   ├── static/
│   │   ├── css/
│   │   │   └── styles.css
│   │   └── uploads/
│   └── templates/
│       ├── auth/
│       │   ├── login.html
│       │   └── register.html
│       ├── base.html
│       ├── chat/
│       │   ├── chat.html
│       │   └── index.html
│       └── errors/
│           ├── 403.html
│           ├── 404.html
│           └── 500.html
│
├── config.py
├── requirements.txt
└── run.py
```

## Dependencies

- Flask: Web framework
- Flask-Login: User session management
- Flask-WTF: Form handling
- Flask-SQLAlchemy: Database ORM
- Pillow: Image processing
- Werkzeug: File security utilities
- Tailwind CSS: Styling
- cryptography: Encryption and digital signatures
## Getting Started

1. **Prerequisites**: Python 3.8+, Git, SQLite
2. **Setup**:
   ```bash
   git clone https://github.com/yourusername/SecureChat.git
   cd SecureChat
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   flask db init && flask db migrate && flask db upgrade
   flask run
   ```
3. Access: `http://127.0.0.1:5000/login`

## Contributing

Fork, create a branch, commit changes, and submit a pull request.

## License

MIT License. See [LICENSE](LICENSE).

## Contact

Open a GitHub issue or email [your.email@example.com](upretynikesh021@gmail.com).
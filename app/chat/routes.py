import bleach
import mimetypes
import os
from datetime import datetime, timezone

import google.generativeai as genai
from flask import (Blueprint, abort, current_app, flash, jsonify, redirect,
                   render_template, request, send_file, send_from_directory,
                   url_for)
from flask_login import current_user, login_required

from app import csrf, db
from app.auth.utils import (decrypt_message, encrypt_message, sign_data,
                            verify_signature)
from app.chat.forms import MessageForm
from app.chat.utils import (allowed_file, generate_file_signature, save_file,
                            verify_uploaded_file)
from app.models import ChatRequest, Message, User

chat_bp = Blueprint('chat', __name__)


# @chat_bp.route('/')
@chat_bp.route('/index')
@login_required
def index():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('chat/index.html', title='Home', users=users)


@chat_bp.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat(user_id):
    # Check if there's an active chat between users
    active_chat = ChatRequest.query.filter(
        ((ChatRequest.sender_id == current_user.id) & (ChatRequest.recipient_id == user_id)) |
        ((ChatRequest.sender_id == user_id) &
         (ChatRequest.recipient_id == current_user.id)),
        ChatRequest.status == 'accepted'
    ).first()

    if not active_chat:
        flash(
            'You need to have an accepted chat request before messaging this user.', 'error')
        return redirect(url_for('chat.index'))

    recipient = User.query.get_or_404(user_id)
    form = MessageForm()

    if request.method == 'POST':
        current_app.logger.debug(
            f"Form submitted: message={form.message.data}, file_data={form.file_data.data}")

        if form.validate_on_submit():
            if not form.message.data and not form.file_data.data:
                current_app.logger.error("No message or file provided")
                flash('Please enter a message or select a file.', 'error')
                return redirect(url_for('chat.chat', user_id=user_id))

            file_path = None
            file_signature = None
            filename = None

            if form.file_data.data:
                uploaded_file = form.file_data.data
                current_app.logger.info(
                    f"Processing file: {uploaded_file.filename}")

                if not allowed_file(uploaded_file.filename):
                    current_app.logger.warning(
                        f"Disallowed file type: {uploaded_file.filename}")
                    flash(
                        'File type not allowed. Allowed types are: png, jpg, jpeg, gif, pdf, doc, docx, txt', 'warning')
                    return redirect(url_for('chat.chat', user_id=user_id))

                filename, file_path = save_file(uploaded_file, current_user.id)
                if not filename or not file_path:
                    current_app.logger.error("File saving failed")
                    flash('Failed to save the file. Please try again.', 'error')
                    return redirect(url_for('chat.chat', user_id=user_id))

                file_signature = generate_file_signature(
                    file_path, current_user.get_private_key())
                if not file_signature:
                    current_app.logger.error(
                        "File signature generation failed")
                    flash('Failed to generate file signature.', 'error')
                    return redirect(url_for('chat.chat', user_id=user_id))

            # Sanitize the message body to prevent XSS
            raw_msg = form.message.data or ''
            message_body = bleach.clean(
                raw_msg,
                tags=[],  # allow NO tags at all, safest
                attributes={},
                strip=True
            )

            recipient_public_key = recipient.get_public_key()
            encrypted_message = encrypt_message(
                message_body, recipient_public_key) if message_body else ''
            signature = sign_data(
                message_body, current_user.get_private_key()) if message_body else ''

            message = Message(
                sender_id=current_user.id,
                recipient_id=user_id,
                body=message_body,
                encrypted_body=encrypted_message,
                signature=signature,
                is_file=bool(form.file_data.data),
                file_path=file_path,
                file_signature=file_signature
            )

            try:
                db.session.add(message)
                db.session.commit()
                current_app.logger.info(
                    f"Message sent: {message.id}, file: {file_path}")
                flash('Your message has been sent!', 'success')
            except Exception as e:
                current_app.logger.error(f"Database commit error: {str(e)}")
                flash('Failed to send message. Please try again.', 'error')
                db.session.rollback()
                return redirect(url_for('chat.chat', user_id=user_id))

            return redirect(url_for('chat.chat', user_id=user_id))
        else:
            current_app.logger.error(f"Form validation failed: {form.errors}")
            flash(
                'Invalid form submission. Please check your file type or size.', 'error')

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    decrypted_messages = []
    for msg in messages:
        if msg.sender_id == current_user.id:
            decrypted_body = msg.body
            signature_valid = True if not msg.body else True
        else:
            try:
                decrypted_body = decrypt_message(
                    msg.encrypted_body, current_user.get_private_key()) if msg.encrypted_body else ''
                signature_valid = verify_signature(
                    decrypted_body, msg.signature, recipient.get_public_key()) if msg.signature else True
            except Exception as e:
                current_app.logger.error(f"Message decryption error: {str(e)}")
                decrypted_body = "[Error decrypting message]"
                signature_valid = False

        decrypted_messages.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'body': decrypted_body,
            'formatted_timestamp': msg.formatted_timestamp,
            'js_timestamp': msg.js_timestamp,
            'is_file': msg.is_file,
            'file_path': msg.file_path,
            'signature_valid': signature_valid,
            'is_current_user': msg.sender_id == current_user.id
        })

    return render_template('chat/chat.html',
                           title=f'Chat with {recipient.username}',
                           form=form,
                           recipient=recipient,
                           messages=decrypted_messages,
                           users=User.query.filter(User.id != current_user.id).all())


@chat_bp.route('/get_messages/<int:user_id>')
@login_required
def get_messages(user_id):
    recipient = User.query.get_or_404(user_id)

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    decrypted_messages = []
    for msg in messages:
        if msg.sender_id == current_user.id:
            decrypted_body = msg.body
            signature_valid = True if not msg.body else True
        else:
            try:
                decrypted_body = decrypt_message(
                    msg.encrypted_body, current_user.get_private_key()) if msg.encrypted_body else ''
                signature_valid = verify_signature(
                    decrypted_body, msg.signature, recipient.get_public_key()) if msg.signature else True
            except Exception:
                decrypted_body = "[Error decrypting message]"
                signature_valid = False

        decrypted_messages.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'body': decrypted_body,
            'formatted_timestamp': msg.formatted_timestamp,
            'js_timestamp': msg.js_timestamp,
            'is_file': msg.is_file,
            'file_url': url_for('chat.download_file', message_id=msg.id) if msg.is_file else None,
            'filename': os.path.basename(msg.file_path) if msg.file_path else None,
            'signature_valid': signature_valid,
            'is_current_user': msg.sender_id == current_user.id,
            "download_url": url_for('chat.download_file', message_id=msg.id) if msg.is_file else None
        })

    # current_app.logger.debug(
    #     f"Returning {len(decrypted_messages)} messages for user '{recipient.username}' (user_id={user_id})")
    current_app.logger.info(
        f"[Messages] {current_user.username} is retrieving {len(decrypted_messages)} messages with {recipient.username}")


    return jsonify(decrypted_messages)


@chat_bp.route('/preview/<int:message_id>')
@login_required
def preview_file(message_id):
    message = Message.query.get_or_404(message_id)

    if not message.is_file or not message.file_path:
        current_app.logger.error(
            f"No file associated with message ID {message_id}")
        flash('No file associated with this message.', 'error')
        return redirect(url_for('chat.chat', user_id=message.recipient_id))

    safe_path = os.path.normpath(message.file_path)
    if os.path.isabs(safe_path) or '..' in safe_path:
        current_app.logger.error(f"Invalid file path: {message.file_path}")
        flash('Invalid file path.', 'error')
        return redirect(url_for('chat.chat', user_id=message.recipient_id))

    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], safe_path)
    if not os.path.exists(file_path):
        current_app.logger.error(f"File not found: {file_path}")
        flash('File not found on server.', 'error')
        return redirect(url_for('chat.chat', user_id=message.recipient_id))

    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = 'application/octet-stream'

    current_app.logger.info(
        f"Previewing file: {file_path} with MIME: {mime_type}")
    return send_file(file_path, mimetype=mime_type)


@csrf.exempt
@chat_bp.route("/niku-ai", methods=["POST"])
@login_required
def ask_nikugpt():
    """Handle AI assistant requests using Gemini 1.5 Flash API"""
    try:
        # Validate request
        data = request.get_json(force=True)
        if not data:
            current_app.logger.error("No JSON data received")
            return jsonify({"reply": "Invalid request format"}), 400

        user_message = data.get("message")
        if not user_message or not isinstance(user_message, str):
            current_app.logger.error(
                f"Invalid message received: {user_message}")
            return jsonify({"reply": "Please provide a valid message"}), 400

        # Configure Gemini
        api_key = current_app.config["GEMINI_API_KEY"]
        if not api_key:
            current_app.logger.error("Missing Gemini API key")
            return jsonify({"reply": "AI service is not configured properly"}), 500

        genai.configure(api_key=api_key)

        # Model configuration
        generation_config = {
            "temperature": 0.7,
            "top_p": 1,
            "top_k": 32,
            "max_output_tokens": 2048,
        }

        safety_settings = [
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE"
            },
        ]

        # Initialize model with latest Gemini 1.5 Flash
        model = genai.GenerativeModel(
            # model_name="gemini-1.5-flash",
            model_name="gemini-2.5-flash",
            # model_name="gemini-2.5-pro",
            generation_config=generation_config,
            safety_settings=safety_settings
        )

        # Prepare messages with proper content structure
        messages = [{"role": "user", "parts": [{"text": user_message}]}]

        # Enhanced context about the app's security architecture
        app_context = """
        [System Context] You are an AI assistant for a secure chat application with these security features:
        
        **End-to-End Encryption**:
        - Messages encrypted with AES-256 using unique per-message symmetric keys
        - Symmetric keys encrypted with recipients' RSA-2048 public keys
        - Decryption requires recipient's private key
        
        **Digital Signatures**:
        - All messages signed with sender's private key
        - Signature verification using sender's public key
        - File uploads also signed and verified
        
        **PKI Integration**:
        - Unique RSA-2048 key pair per user at registration
        - Private keys stored securely in database (HSMs recommended for production)
        
        **Secure Authentication**:
        - Password hashing with bcrypt
        - Secure session management
        - CSRF protection
        
        **Transport Security**:
        - HTTPS enforcement
        - Security headers (CSP, HSTS)
        - SameSite cookies
        
        **File Upload Security**:
        - File type validation
        - Secure filename handling
        - Digital signatures for uploaded files
        
        **Backend Stack**:
        - Flask backend with SQLAlchemy ORM
        - Google Gemini AI integration
        - RSA/AES hybrid cryptosystem
        """

        # Add context for security/tech-related queries
        security_keywords = [
            "app", "application", "secure", "encryption", "flask",
            "aes", "rsa", "signature", "key", "cryptography",
            "security", "pki", "authentication", "https", "file",
            "decrypt", "encrypt", "bcrypt", "csrf", "hsts", "csp"
        ]

        if any(kw in user_message.lower() for kw in security_keywords):
            # Insert context as first message in conversation
            messages.insert(
                0, {"role": "user", "parts": [{"text": app_context}]})

        # Generate response with correct content structure
        response = model.generate_content(messages)

        if not response.text:
            current_app.logger.error("Empty response from Gemini API")
            return jsonify({"reply": "I couldn't generate a response. Please try again."}), 500

        current_app.logger.info(
            f"AI response generated for query: {user_message}")
        return jsonify({"reply": response.text})

    except genai.types.BlockedPromptException as e:
        current_app.logger.warning(f"Blocked prompt: {str(e)}")
        return jsonify({"reply": "I can't respond to that request due to content safety restrictions."}), 400

    except Exception as e:
        current_app.logger.error(f"Gemini API error: {str(e)}", exc_info=True)
        return jsonify({"reply": "⚠️ AI is resting. Too many questions today. Please wait 24 hours"}), 500


@chat_bp.route('/download/<int:message_id>')
@login_required
def download_file(message_id):
    message = Message.query.get_or_404(message_id)

    if not message.is_file or not message.file_path:
        current_app.logger.error(
            f"No file associated with message ID {message_id}")
        flash('No file associated with this message.', 'error')
        return redirect(url_for('chat.chat', user_id=message.recipient_id))

    safe_path = os.path.normpath(message.file_path)
    if os.path.isabs(safe_path) or '..' in safe_path:
        current_app.logger.error(f"Invalid file path: {message.file_path}")
        flash('Invalid file path.', 'error')
        return redirect(url_for('chat.chat', user_id=message.recipient_id))

    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], safe_path)
    if not os.path.exists(file_path):
        current_app.logger.error(f"File not found: {file_path}")
        flash('File not found on server.', 'error')
        return redirect(url_for('chat.chat', user_id=message.recipient_id))

    # Verify signature if needed (optional, same as before)
    if message.file_signature:
        sender = User.query.get(message.sender_id)
        if not sender:
            current_app.logger.error(
                f"Sender not found for message ID {message_id}")
            flash('Sender info unavailable.', 'error')
            return redirect(url_for('chat.chat', user_id=message.recipient_id))
        try:
            if not verify_uploaded_file(safe_path, message.file_signature, sender.get_public_key()):
                current_app.logger.error(
                    f"Signature verification failed for file: {file_path}")
                flash('File signature verification failed.', 'error')
                return redirect(url_for('chat.chat', user_id=message.recipient_id))
        except Exception as e:
            current_app.logger.error(f"Signature check failed: {e}")
            flash('Error verifying file signature.', 'error')
            return redirect(url_for('chat.chat', user_id=message.recipient_id))

    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = 'application/octet-stream'

    current_app.logger.info(
        f"Downloading file: {file_path} with MIME: {mime_type}")
    return send_file(
        file_path,
        as_attachment=True,
        download_name=os.path.basename(file_path),
        mimetype=mime_type
    )


@chat_bp.route('/send_request/<int:recipient_id>', methods=['POST'])
@login_required
def send_request(recipient_id):
    recipient = User.query.get_or_404(recipient_id)

    # Check for existing requests
    existing_request = ChatRequest.query.filter(
        ChatRequest.sender_id == current_user.id,
        ChatRequest.recipient_id == recipient_id
    ).first()

    if existing_request:
        flash('Request already exists', 'info')
        return redirect(url_for('chat.index'))

    # Generate consistent timestamp string
    created_at = datetime.now(timezone.utc)
    created_at_str = created_at.isoformat()
    request_data = f"CHAT_REQUEST:{current_user.id}:{recipient_id}:{created_at_str}"

    try:
        signature = sign_data(request_data, current_user.get_private_key())
    except Exception as e:
        current_app.logger.error(f"Failed to sign request: {str(e)}")
        flash('Failed to create request', 'error')
        return redirect(url_for('chat.index'))

    chat_request = ChatRequest(
        sender_id=current_user.id,
        recipient_id=recipient_id,
        created_at=created_at,
        created_at_str=created_at_str,  # ✅ New field added
        signature=signature,
        status='pending'
    )

    try:
        db.session.add(chat_request)
        db.session.commit()
        flash('Chat request sent!', 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Database error: {str(e)}")
        flash('Failed to send request', 'error')

    return redirect(url_for('chat.index'))


@chat_bp.route('/respond_request/<int:request_id>', methods=['POST'])
@login_required
def respond_chat_request(request_id):
    chat_request = ChatRequest.query.get_or_404(request_id)

    current_app.logger.debug(f"ChatRequest Object: {vars(chat_request)}")
    current_app.logger.debug(f"Signature from DB: {chat_request.signature}")

    if current_user.id != chat_request.recipient_id:
        abort(403)

    action = request.form.get('action')
    if action != 'accept':
        chat_request.status = 'rejected'
        db.session.commit()
        flash('Request rejected', 'info')
        return redirect(url_for('chat.index'))

    # ✅ Use stored `created_at_str` instead of `created_at.isoformat()`
    original_data = f"CHAT_REQUEST:{chat_request.sender_id}:{chat_request.recipient_id}:{chat_request.created_at_str}"
    current_app.logger.debug(f"Reconstructed original data: {original_data}")

    sender = User.query.get(chat_request.sender_id)
    if not sender:
        flash('Sender not found', 'error')
        return redirect(url_for('chat.index'))

    current_app.logger.debug("Attempting signature verification...")
    if not verify_signature(original_data, chat_request.signature, sender.get_public_key()):
        # Optional debug info if needed
        try:
            # NOTE: You CANNOT regenerate signature unless you have sender's private key
            new_signature = sign_data(
                original_data, sender.get_private_key())  # Only for debug
            current_app.logger.debug(
                f"Newly generated signature: {new_signature}")
            current_app.logger.debug(
                f"Original signature: {chat_request.signature}")
            current_app.logger.debug(
                f"Signatures match: {new_signature == chat_request.signature}")
        except Exception as e:
            current_app.logger.error(f"Resigning failed: {str(e)}")

        flash('Request verification failed', 'error')
        return redirect(url_for('chat.index'))

    chat_request.status = 'accepted'
    db.session.commit()
    flash('Request accepted!', 'success')
    return redirect(url_for('chat.index'))


def test_signature(user_id):
    """Test endpoint to verify key functionality"""
    user = User.query.get_or_404(user_id)

    test_data = "TEST_SIGNATURE_DATA"
    current_app.logger.debug(f"Testing with data: {test_data}")

    try:
        # Sign and verify with the same key
        signature = sign_data(test_data, user.get_private_key())
        current_app.logger.debug(f"Generated signature: {signature}")

        is_valid = verify_signature(
            test_data, signature, user.get_public_key())
        return jsonify({
            'success': is_valid,
            'public_key': user.public_key,
            'test_data': test_data,
            'signature': signature,
            'verification_result': is_valid
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

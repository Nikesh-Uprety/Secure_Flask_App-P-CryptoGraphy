from datetime import datetime, timezone
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app, send_file, send_from_directory
from flask_login import current_user, login_required
from app import db
from app.models import User, Message
from app.chat.forms import MessageForm
from app.auth.utils import encrypt_message, decrypt_message, sign_data, verify_signature
from app.chat.utils import save_file, generate_file_signature, verify_uploaded_file
import os
import mimetypes

chat_bp = Blueprint('chat', __name__)

@chat_bp.route('/')
@chat_bp.route('/index')
@login_required
def index():
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('chat/index.html', title='Home', users=users)

@chat_bp.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def chat(user_id):
    recipient = User.query.get_or_404(user_id)
    form = MessageForm()
    
    if request.method == 'POST':
        current_app.logger.debug(f"Form submitted: message={form.message.data}, file_data={form.file_data.data}")
        if form.validate_on_submit():
            if not form.message.data and not form.file_data.data:
                current_app.logger.error("No message or file provided")
                flash('Please enter a message or select a file.', 'error')
                return redirect(url_for('chat.chat', user_id=user_id))
            
            file_path = None
            file_signature = None
            filename = None
            
            if form.file_data.data:
                current_app.logger.info(f"Processing file: {form.file_data.data.filename}")
                filename, file_path = save_file(form.file_data.data, current_user.id)
                if not filename or not file_path:
                    current_app.logger.error("File saving failed")
                    flash('Failed to save the file. Please try again.', 'error')
                    return redirect(url_for('chat.chat', user_id=user_id))
                
                file_signature = generate_file_signature(file_path, current_user.get_private_key())
                if not file_signature:
                    current_app.logger.error("File signature generation failed")
                    flash('Failed to generate file signature.', 'error')
                    return redirect(url_for('chat.chat', user_id=user_id))

            message_body = form.message.data or ''
            recipient_public_key = recipient.get_public_key()
            encrypted_message = encrypt_message(message_body, recipient_public_key) if message_body else ''
            signature = sign_data(message_body, current_user.get_private_key()) if message_body else ''
            
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
                current_app.logger.info(f"Message sent: {message.id}, file: {file_path}")
                flash('Your message has been sent!', 'success')
            except Exception as e:
                current_app.logger.error(f"Database commit error: {str(e)}")
                flash('Failed to send message. Please try again.', 'error')
                db.session.rollback()
                return redirect(url_for('chat.chat', user_id=user_id))
            
            return redirect(url_for('chat.chat', user_id=user_id))
        else:
            current_app.logger.error(f"Form validation failed: {form.errors}")
            flash('Invalid form submission. Please check your file type or size.', 'error')
    
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
                decrypted_body = decrypt_message(msg.encrypted_body, current_user.get_private_key()) if msg.encrypted_body else ''
                signature_valid = verify_signature(decrypted_body, msg.signature, recipient.get_public_key()) if msg.signature else True
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
                decrypted_body = decrypt_message(msg.encrypted_body, current_user.get_private_key()) if msg.encrypted_body else ''
                signature_valid = verify_signature(decrypted_body, msg.signature, recipient.get_public_key()) if msg.signature else True
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
            'is_current_user': msg.sender_id == current_user.id
        })
    
    current_app.logger.debug(f"Returning {len(decrypted_messages)} messages for user {user_id}")
    return jsonify(decrypted_messages)


@chat_bp.route('/preview/<int:message_id>')
@login_required
def preview_file(message_id):
    message = Message.query.get_or_404(message_id)

    if not message.is_file or not message.file_path:
        current_app.logger.error(f"No file associated with message ID {message_id}")
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

    current_app.logger.info(f"Previewing file: {file_path} with MIME: {mime_type}")
    return send_file(file_path, mimetype=mime_type)

@chat_bp.route('/download/<int:message_id>')
@login_required
def download_file(message_id):
    message = Message.query.get_or_404(message_id)

    if not message.is_file or not message.file_path:
        current_app.logger.error(f"No file associated with message ID {message_id}")
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
            current_app.logger.error(f"Sender not found for message ID {message_id}")
            flash('Sender info unavailable.', 'error')
            return redirect(url_for('chat.chat', user_id=message.recipient_id))
        try:
            if not verify_uploaded_file(safe_path, message.file_signature, sender.get_public_key()):
                current_app.logger.error(f"Signature verification failed for file: {file_path}")
                flash('File signature verification failed.', 'error')
                return redirect(url_for('chat.chat', user_id=message.recipient_id))
        except Exception as e:
            current_app.logger.error(f"Signature check failed: {e}")
            flash('Error verifying file signature.', 'error')
            return redirect(url_for('chat.chat', user_id=message.recipient_id))

    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = 'application/octet-stream'

    current_app.logger.info(f"Downloading file: {file_path} with MIME: {mime_type}")
    return send_file(
        file_path,
        as_attachment=True,
        download_name=os.path.basename(file_path),
        mimetype=mime_type
    )

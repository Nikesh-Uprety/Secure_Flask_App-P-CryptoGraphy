from flask import current_app
from werkzeug.utils import secure_filename
import os
from PIL import Image
from app.auth.utils import sign_file, verify_file_signature

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'}


def allowed_file(filename):
    current_app.logger.debug(f"Checking if file {filename} is allowed")
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def verify_file_extension(file_stream):
    current_app.logger.debug("Verifying file extension by header")
    try:
        header = file_stream.read(512)  # read more to help with detection
        file_stream.seek(0)

        if header.startswith(b'\xFF\xD8'):
            return 'jpg'
        elif header.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'png'
        elif header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
            return 'gif'
        elif header.startswith(b'%PDF-'):
            return 'pdf'
        # For text and docx, rely on file extension since headers are not reliable
        return None
    except Exception as e:
        current_app.logger.error(
            f"File extension verification error: {str(e)}")
        return None


def save_file(file, user_id):
    current_app.logger.debug(
        f"Attempting to save file: {file.filename if file else 'None'}, user_id: {user_id}")
    if not file or not allowed_file(file.filename):
        current_app.logger.error(
            f"File {file.filename if file else 'None'} not allowed: extension not in {ALLOWED_EXTENSIONS}")
        return None, None

    # Ensure filename is secure
    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[1].lower()

    # Extension validation (based on content only for images/pdf)
    header_ext = verify_file_extension(file)
    if header_ext:
        if header_ext != ext and header_ext in {'png', 'jpg', 'jpeg', 'gif', 'pdf'}:
            current_app.logger.error(
                f"Mismatch between file extension and detected type for {file.filename}")
            return None, None

    upload_dir = os.path.join(
        current_app.config['UPLOAD_FOLDER'], str(user_id))
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, filename)
    relative_path = os.path.join(str(user_id), filename)

    try:
        # Save images with resizing
        if ext in {'png', 'jpg', 'jpeg', 'gif'}:
            img = Image.open(file)
            img.thumbnail((800, 800))
            img.save(file_path)
            current_app.logger.info(f"Image saved: {file_path}")
        else:
            file.seek(0)  # Ensure pointer reset before saving non-image files
            with open(file_path, 'wb') as f:
                f.write(file.read())
            current_app.logger.info(f"File saved: {file_path}")

        if not os.path.exists(file_path):
            current_app.logger.error(
                f"File {file_path} was not saved correctly")
            return None, None
        if not os.access(file_path, os.R_OK):
            current_app.logger.error(f"File {file_path} is not readable")
            return None, None

        current_app.logger.debug(f"File saved successfully: {relative_path}")
        return filename, relative_path.replace('\\', '/')

    except Exception as e:
        current_app.logger.error(
            f"File save error for {file.filename}: {str(e)}")
        return None, None


def generate_file_signature(file_path, private_key):
    current_app.logger.debug(f"Generating signature for file: {file_path}")
    try:
        full_path = os.path.join(
            current_app.config['UPLOAD_FOLDER'], file_path)
        with open(full_path, 'rb') as f:
            file_data = f.read()
        signature = sign_file(file_data, private_key)
        current_app.logger.info(f"Generated signature for file: {file_path}")
        return signature
    except Exception as e:
        current_app.logger.error(
            f"Signature generation error for {file_path}: {str(e)}")
        return None


def verify_uploaded_file(file_path, signature, public_key):
    current_app.logger.debug(f"Verifying signature for file: {file_path}")
    try:
        full_path = os.path.join(
            current_app.config['UPLOAD_FOLDER'], file_path)
        with open(full_path, 'rb') as f:
            file_data = f.read()
        verified = verify_file_signature(file_data, signature, public_key)
        current_app.logger.info(
            f"File signature verification for {file_path}: {'Success' if verified else 'Failed'}")
        return verified
    except Exception as e:
        current_app.logger.error(
            f"File verification error for {file_path}: {str(e)}")
        return False

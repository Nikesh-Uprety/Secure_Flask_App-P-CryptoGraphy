from flask import current_app
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

def generate_symmetric_key():
    current_app.logger.debug("Generating 256-bit AES symmetric key")
    return os.urandom(32)

def encrypt_message(message, public_key):
    try:
        current_app.logger.debug("Encrypting message")
        symmetric_key = generate_symmetric_key()
        iv = os.urandom(16)

        cipher = Cipher(
            algorithms.AES(symmetric_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

        encrypted_key = public_key.encrypt(
            symmetric_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        combined = iv + encrypted_key + encrypted_message
        result = base64.b64encode(combined).decode('utf-8')
        current_app.logger.info("Message encrypted successfully")
        return result
    except Exception as e:
        current_app.logger.error(f"Message encryption error: {str(e)}")
        raise

def decrypt_message(encrypted_message, private_key):
    try:
        current_app.logger.debug("Decrypting message")
        combined = base64.b64decode(encrypted_message.encode('utf-8'))

        iv = combined[:16]
        encrypted_key = combined[16:272]
        ciphertext = combined[272:]

        symmetric_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(
            algorithms.AES(symmetric_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()
        current_app.logger.info("Message decrypted successfully")
        return message.decode('utf-8')
    except Exception as e:
        current_app.logger.error(f"Message decryption error: {str(e)}")
        raise

def sign_data(data, private_key):
    try:
        current_app.logger.debug("Signing data")
        signature = private_key.sign(
            data.encode('utf-8'),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        result = base64.b64encode(signature).decode('utf-8')
        current_app.logger.info("Data signed successfully")
        return result
    except Exception as e:
        current_app.logger.error(f"Data signing error: {str(e)}")
        raise

def verify_signature(data, signature, public_key):
    try:
        current_app.logger.debug("Verifying signature")
        public_key.verify(
            base64.b64decode(signature.encode('utf-8')),
            data.encode('utf-8'),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        current_app.logger.info("Signature verified successfully")
        return True
    except Exception as e:
        current_app.logger.error(f"Signature verification error: {str(e)}")
        return False

def sign_file(file_data, private_key):
    try:
        current_app.logger.debug("Signing file data")
        signature = private_key.sign(
            file_data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        result = base64.b64encode(signature).decode('utf-8')
        current_app.logger.info("File signed successfully")
        return result
    except Exception as e:
        current_app.logger.error(f"File signing error: {str(e)}")
        raise

def verify_file_signature(file_data, signature, public_key):
    try:
        current_app.logger.debug("Verifying file signature")
        public_key.verify(
            base64.b64decode(signature.encode('utf-8')),
            file_data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        current_app.logger.info("File signature verified successfully")
        return True
    except Exception as e:
        current_app.logger.error(f"File signature verification error: {str(e)}")
        return False
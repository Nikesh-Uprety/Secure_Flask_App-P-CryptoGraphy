import hashlib
from flask import current_app
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
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
    """
    Sign data using RSA private key and return base64-encoded signature.
    """
    try:
        current_app.logger.debug(f"[SIGN] Data to sign (repr): {repr(data)}")

        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data

        signature = private_key.sign(
            data_bytes,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        signature_b64 = base64.b64encode(signature).decode('utf-8')
        current_app.logger.info("Data signed successfully")
        current_app.logger.debug(f"[SIGN] Signature (b64): {signature_b64}")
        return signature_b64

    except Exception as e:
        current_app.logger.error(
            f"[SIGN] Data signing error: {str(e)}", exc_info=True)
        raise


def verify_signature(data, signature, public_key):
    """
    Verify a digital signature with detailed debugging.
    Returns True if valid, False otherwise.
    """
    try:
        current_app.logger.debug(f"[VERIFY] Input data (repr): {repr(data)}")
        current_app.logger.debug(
            f"[VERIFY] Input signature (b64): {signature}")

        # Serialize public key and log its fingerprint
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = hashlib.sha256(public_key_pem).hexdigest()
        current_app.logger.debug(
            f"[VERIFY] Public key SHA256 fingerprint: {fingerprint[:8]}...{fingerprint[-8:]}")

        # Encode data
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data

        # Decode signature from base64
        try:
            if isinstance(signature, str):
                signature_bytes = base64.b64decode(signature)
            else:
                signature_bytes = signature
            current_app.logger.debug(
                f"[VERIFY] Decoded signature length: {len(signature_bytes)} bytes")
        except Exception as decode_error:
            current_app.logger.error(
                f"[VERIFY] Signature base64 decode failed: {str(decode_error)}")
            return False

        # Verify the signature
        public_key.verify(
            signature_bytes,
            data_bytes,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        current_app.logger.info("[VERIFY] Signature verification successful")
        return True

    except Exception as e:
        current_app.logger.error(
            f"[VERIFY] Signature verification failed: {str(e)}", exc_info=True)
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
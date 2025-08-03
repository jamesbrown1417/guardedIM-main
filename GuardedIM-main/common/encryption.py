import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_MESSAGE_SIZE = 64 * 8 #64KB
MAX_FILE_SIZE = 5 * 1024**2 #5MB

def check_file_size(b64_data: str) -> bool:
    try:
        if not b64_data:
            return False
        raw_bytes = base64.b64decode(b64_data + "===")
        return len(raw_bytes) <= MAX_FILE_SIZE
    except Exception as e:
        print(f"[check_file_size] Failed base64 decode: {e}")
        return False

def check_message_size(message: str) -> bool:
    return len(message.encode('utf-8')) <= MAX_MESSAGE_SIZE

def generate_aes_key() -> bytes:
    return os.urandom(32)

def encrypt_message(message: str, aes_key: bytes) -> bytes:
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, message.encode('utf-8'), None)

def decrypt_message(encrypted: bytes, aes_key: bytes) -> str:
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')


def rsa_encrypt_key(public_key_bytes: bytes, aes_key:bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_key_bytes)
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

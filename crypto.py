# crypto.py
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import base64


# RSA functions
def generate_key_pair():
    """Generate a 2048-bit RSA key pair"""
    key = RSA.generate(2048)
    public_pem = key.public_key().export_key().decode()
    private_pem = key.export_key().decode()
    return public_pem, private_pem


def rsa_encrypt(plain_text: bytes, public_pem: str) -> str:
    """Encrypt data bytes with RSA public key"""
    public_key = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(public_key)
    cipher_text = cipher.encrypt(plain_text)
    return base64.b64encode(cipher_text).decode()


def rsa_decrypt(cipher_text_b64: str, private_pem: str) -> bytes:
    """Decrypt data using RSA private key"""
    cipher_text = base64.b64decode(cipher_text_b64)
    private_key = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(private_key)
    plain_text = cipher.decrypt(cipher_text)
    return plain_text


# aes_key = get_random_bytes(32)
# public_pem, private_pem = generate_key_pair()
# print(aes_key)
# cipher_text = rsa_encrypt(aes_key, public_pem)
# plain_text = rsa_decrypt(cipher_text, private_pem)
# print(f"Cipher text: {cipher_text}")
# print(f"Plain text: {plain_text}")


# AES functions
def aes_encrypt(plain_text: str, key: bytes) -> str:
    """Encrypt text using AES-256-CBC"""
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return base64.b64encode(iv + cipher_text).decode()


def aes_decrypt(cipher_text_b64, key: bytes) -> str:
    """Decrypt text using AES-256-CBC"""
    iv_cipher_text = base64.b64decode(cipher_text_b64)
    iv, cipher_text = iv_cipher_text[:16], iv_cipher_text[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(cipher_text), AES.block_size)
    return plain_text.decode()


# message = "Hello World"
# cipher_text = aes_encrypt(message, aes_key)
# plain_text = aes_decrypt(cipher_text, aes_key)

# print(cipher_text)
# print(plain_text)


# Signature message
def create_signature(private_pem: str, message: str) -> str:
    private_key = RSA.import_key(private_pem)
    message_hash = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(message_hash)
    return base64.b64encode(signature).decode()


def verify_signature(public_pem: str, signature_b64: str, message: str) -> bool:
    public_key = RSA.import_key(public_pem)
    signature = base64.b64decode(signature_b64)
    try:
        pkcs1_15.new(public_key).verify(SHA256.new(message.encode()), signature)
        return True
    except (ValueError, TypeError):
        return False

# app/crypto.py
import os
import json
import base64
from typing import Tuple

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Key generation / serialization ------------------------------------------------

def ensure_keys_folder(path: str):
    os.makedirs(path, exist_ok=True)

# RSA
def generate_rsa(key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

# ECC (P-256)
def generate_ec(curve: ec.EllipticCurve = ec.SECP256R1()):
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key

def private_key_to_pem(private_key, password: bytes = None) -> bytes:
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    return pem

def public_key_to_pem(public_key) -> bytes:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def load_private_key(pem_data: bytes, password: bytes = None):
    return serialization.load_pem_private_key(pem_data, password=password)

def load_public_key(pem_data: bytes):
    return serialization.load_pem_public_key(pem_data)

# --- RSA encryption / decryption --------------------------------------------------

def rsa_encrypt(public_key, plaintext: bytes) -> str:
    """
    Encrypt with RSA-OAEP, return base64 string of ciphertext.
    """
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(private_key, b64_ciphertext: str) -> bytes:
    ciphertext = base64.b64decode(b64_ciphertext)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# --- ECC hybrid encryption (ECDH + AES-GCM) -------------------------------------

def _derive_shared_key_ecdh(private_key, peer_public_key, length: int = 32) -> bytes:
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    # derive symmetric key from shared secret
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'ecdh-encryption',
    )
    return hkdf.derive(shared_secret)

def ec_encrypt(recipient_public_key, plaintext: bytes) -> str:
    """
    ECIES-like hybrid:
    - generate ephemeral EC key
    - derive shared key via ECDH
    - encrypt with AES-GCM
    - package ephemeral public key PEM + nonce + ciphertext (base64 JSON), then base64-encode the whole JSON bytes
    """
    # ephemeral key
    ephemeral_private = ec.generate_private_key(recipient_public_key.curve)
    ephemeral_public = ephemeral_private.public_key()

    # derive symmetric key
    sym_key = _derive_shared_key_ecdh(ephemeral_private, recipient_public_key)

    # AES-GCM encrypt
    aesgcm = AESGCM(sym_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)  # ciphertext includes tag

    # serialize ephemeral public key to PEM
    eph_pub_pem = public_key_to_pem(ephemeral_public).decode('utf-8')

    payload = {
        'ephemeral_pub': eph_pub_pem,
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }
    payload_bytes = json.dumps(payload).encode('utf-8')
    return base64.b64encode(payload_bytes).decode('utf-8')

def ec_decrypt(recipient_private_key, b64_payload: str) -> bytes:
    payload_bytes = base64.b64decode(b64_payload)
    payload = json.loads(payload_bytes.decode('utf-8'))

    eph_pub_pem = payload['ephemeral_pub'].encode('utf-8')
    ephemeral_public = load_public_key(eph_pub_pem)

    nonce = base64.b64decode(payload['nonce'])
    ciphertext = base64.b64decode(payload['ciphertext'])

    sym_key = _derive_shared_key_ecdh(recipient_private_key, ephemeral_public)
    aesgcm = AESGCM(sym_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext

# --- Signatures (RSA-PSS and ECDSA) ---------------------------------------------

def sign_rsa(private_key, data: bytes) -> str:
    sig = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode('utf-8')

def verify_rsa(public_key, data: bytes, b64_signature: str) -> bool:
    sig = base64.b64decode(b64_signature)
    try:
        public_key.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def sign_ecdsa(private_key, data: bytes) -> str:
    sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode('utf-8')

def verify_ecdsa(public_key, data: bytes, b64_signature: str) -> bool:
    sig = base64.b64decode(b64_signature)
    try:
        public_key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

# --- Utility helpers -------------------------------------------------------------

def save_key_to_file(path: str, pem_bytes: bytes):
    with open(path, 'wb') as f:
        f.write(pem_bytes)

def load_pem_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()

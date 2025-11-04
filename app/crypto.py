# app/crypto.py
import os
import json
import base64
from typing import Tuple

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Generación de claves / serialización --------------------------------------

def ensure_keys_folder(path: str):
    # Asegura que el directorio de claves exista, si no, lo crea
    os.makedirs(path, exist_ok=True)

# RSA
def generate_rsa(key_size: int = 2048):
    # Genera un par de claves RSA (privada y pública)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

# ECC (Curva P-256)
def generate_ec(curve: ec.EllipticCurve = ec.SECP256R1()):
    # Genera un par de claves ECC (privada y pública) usando la curva especificada
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    return private_key, public_key

def private_key_to_pem(private_key, password: bytes = None) -> bytes:
    # Convierte una clave privada en formato PEM, con cifrado opcional si se proporciona una contraseña
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc
    )
    return pem

def public_key_to_pem(public_key) -> bytes:
    # Convierte una clave pública en formato PEM
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def load_private_key(pem_data: bytes, password: bytes = None):
    # Carga una clave privada desde un archivo PEM, con una contraseña opcional
    return serialization.load_pem_private_key(pem_data, password=password)

def load_public_key(pem_data: bytes):
    # Carga una clave pública desde un archivo PEM
    return serialization.load_pem_public_key(pem_data)

# --- Cifrado / descifrado RSA ----------------------------------------------------

def rsa_encrypt(public_key, plaintext: bytes) -> str:
    """
    Cifra con RSA-OAEP, devuelve una cadena en base64 del texto cifrado.
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
    # Descifra un texto cifrado con RSA-OAEP (en formato base64)
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

# --- Cifrado híbrido ECC (ECDH + AES-GCM) --------------------------------------

def _derive_shared_key_ecdh(private_key, peer_public_key, length: int = 32) -> bytes:
    # Deriva una clave compartida mediante ECDH (Elliptic Curve Diffie-Hellman)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    # Deriva una clave simétrica a partir del secreto compartido usando HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'ecdh-encryption',
    )
    return hkdf.derive(shared_secret)

def ec_encrypt(recipient_public_key, plaintext: bytes) -> str:
    """
    Cifrado híbrido ECIES (Elliptic Curve Integrated Encryption Scheme):
    - genera una clave EC efímera
    - deriva la clave compartida mediante ECDH
    - cifra con AES-GCM
    - empaqueta la clave pública efímera en PEM, el nonce y el texto cifrado (en formato base64 JSON),
      luego codifica todo en base64
    """
    # Genera una clave efímera
    ephemeral_private = ec.generate_private_key(recipient_public_key.curve)
    ephemeral_public = ephemeral_private.public_key()

    # Deriva la clave simétrica
    sym_key = _derive_shared_key_ecdh(ephemeral_private, recipient_public_key)

    # Cifrado AES-GCM
    aesgcm = AESGCM(sym_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)  # El texto cifrado incluye la etiqueta

    # Serializa la clave pública efímera a formato PEM
    eph_pub_pem = public_key_to_pem(ephemeral_public).decode('utf-8')

    payload = {
        'ephemeral_pub': eph_pub_pem,
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }
    payload_bytes = json.dumps(payload).encode('utf-8')
    return base64.b64encode(payload_bytes).decode('utf-8')

def ec_decrypt(recipient_private_key, b64_payload: str) -> bytes:
    # Descifra el mensaje cifrado usando ECDH + AES-GCM
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

# --- Firmas (RSA-PSS y ECDSA) ---------------------------------------------------

def sign_rsa(private_key, data: bytes) -> str:
    # Firma los datos con la clave privada RSA usando PSS
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
    # Verifica la firma RSA
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
    # Firma los datos con la clave privada ECDSA
    sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode('utf-8')

def verify_ecdsa(public_key, data: bytes, b64_signature: str) -> bool:
    # Verifica la firma ECDSA
    sig = base64.b64decode(b64_signature)
    try:
        public_key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

# --- Funciones auxiliares --------------------------------------------------------

def save_key_to_file(path: str, pem_bytes: bytes):
    # Guarda la clave en un archivo en formato PEM
    with open(path, 'wb') as f:
        f.write(pem_bytes)

def load_pem_file(path: str) -> bytes:
    # Carga un archivo PEM
    with open(path, 'rb') as f:
        return f.read()

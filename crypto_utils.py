# crypto_utils.py

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

def generar_claves():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def guardar_clave_privada(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def guardar_clave_publica(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def cargar_clave_privada(filename):
    with open(filename, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def cargar_clave_publica(filename):
    with open(filename, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def firmar_documento(document_bytes, private_key):
    signature = private_key.sign(
        document_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(signature)
"""
def verificar_firma(document_bytes, signature_b64, public_key):
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            document_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
    """
def firmar_hash(hash_bytes, private_key):
    signature = private_key.sign(
        hash_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature  # devuelves firma binaria

def verificar_firma(hash_bytes, signature, public_key):
    try:
        public_key.verify(
            signature,
            hash_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False


def calcular_hash(document_bytes):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(document_bytes)
    return digest.finalize().hex()

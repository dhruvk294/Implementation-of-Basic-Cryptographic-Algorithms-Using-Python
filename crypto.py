# Demonstrates AES-GCM, RSA (OAEP) encryption/decryption and RSA signing (PSS) and SHA-256 hashing and HMAC.
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
import base64
# A) AES-GCM (symmetric)
def aes_encrypt_gcm(plaintext: bytes, key: bytes):
    # key must be 16/24/32 bytes for AES-128/192/256
    iv = get_random_bytes(12)  # 12 bytes recommended for GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # return base64-friendly package
    return base64.b64encode(iv + tag + ciphertext).decode()
def aes_decrypt_gcm(b64package: str, key: bytes):
    data = base64.b64decode(b64package)
    iv = data[:12]
    tag = data[12:28]       # GCM tag is 16 bytes
    ciphertext = data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext
# B) RSA (asymmetric)
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()
    return private_pem, public_pem
def rsa_encrypt(message: bytes, public_pem: bytes):
    pub = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    return base64.b64encode(cipher.encrypt(message)).decode()
def rsa_decrypt(b64cipher: str, private_pem: bytes):
    priv = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    return cipher.decrypt(base64.b64decode(b64cipher))
def rsa_sign(message: bytes, private_pem: bytes):
    priv = RSA.import_key(private_pem)
    h = SHA256.new(message)
    signature = pss.new(priv).sign(h)
    return base64.b64encode(signature).decode()
def rsa_verify(message: bytes, b64signature: str, public_pem: bytes):
    pub = RSA.import_key(public_pem)
    h = SHA256.new(message)
    signature = base64.b64decode(b64signature)
    verifier = pss.new(pub)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
# C) Hashing & HMAC
def sha256_hex(data: bytes):
    h = SHA256.new(data)
    return h.hexdigest()
def hmac_sha256_hex(key: bytes, data: bytes):
    hm = HMAC.new(key, digestmod=SHA256)
    hm.update(data)
    return hm.hexdigest()
# Demo usage
def demo():
    print("=== AES-GCM demo ===")
    key = get_random_bytes(32)  # AES-256
    plaintext = b"Secret message for AES-GCM"
    pkg = aes_encrypt_gcm(plaintext, key)
    print("Encrypted (base64):", pkg)
    pt = aes_decrypt_gcm(pkg, key)
    print("Decrypted:", pt)

    print("\n=== RSA demo ===")
    priv_pem, pub_pem = generate_rsa_keypair(2048)
    message = b"Hello RSA!"
    enc = rsa_encrypt(message, pub_pem)
    print("Encrypted (base64):", enc)
    dec = rsa_decrypt(enc, priv_pem)
    print("Decrypted:", dec)

    sig = rsa_sign(message, priv_pem)
    print("Signature (base64):", sig)
    ok = rsa_verify(message, sig, pub_pem)
    print("Signature valid?", ok)

    print("\n=== Hash & HMAC demo ===")
    print("SHA-256:", sha256_hex(b"data to hash"))
    hmac_key = get_random_bytes(32)
    print("HMAC-SHA256:", hmac_sha256_hex(hmac_key, b"message"))
if __name__ == "__main__":
    demo()

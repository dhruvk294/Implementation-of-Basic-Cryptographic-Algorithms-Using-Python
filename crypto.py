from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
import base64

# =========================
# A) AES-GCM (Symmetric)
# =========================

def aes_encrypt_gcm(plaintext: bytes, key: bytes):
    iv = get_random_bytes(12)  # Recommended nonce size for GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return base64.b64encode(iv + tag + ciphertext).decode()

def aes_decrypt_gcm(b64package: str, key: bytes):
    data = base64.b64decode(b64package)
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag)

# =========================
# B) RSA (Asymmetric)
# =========================

def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key.export_key(), key.publickey().export_key()

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
    try:
        pss.new(pub).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# =========================
# C) Hashing & HMAC
# =========================

def sha256_hex(data: bytes):
    return SHA256.new(data).hexdigest()

def hmac_sha256_hex(key: bytes, data: bytes):
    hm = HMAC.new(key, digestmod=SHA256)
    hm.update(data)
    return hm.hexdigest()

# =========================
# CLI Interface
# =========================

def menu():
    print("\n=== Cryptography with Python ===")
    print("1. AES-GCM Encrypt")
    print("2. AES-GCM Decrypt")
    print("3. RSA Encrypt")
    print("4. RSA Decrypt")
    print("5. RSA Sign")
    print("6. RSA Verify")
    print("7. SHA-256 Hash")
    print("8. HMAC-SHA256")
    print("0. Exit")

def main():
    # Session keys (demo purpose)
    aes_key = get_random_bytes(32)  # AES-256
    rsa_private, rsa_public = generate_rsa_keypair()

    print("🔐 Keys generated for this session.")

    while True:
        menu()
        choice = input("Select an option: ").strip()

        if choice == "1":
            msg = input("Enter plaintext: ").encode()
            encrypted = aes_encrypt_gcm(msg, aes_key)
            print("\nEncrypted (base64):", encrypted)

        elif choice == "2":
            enc = input("Enter base64 ciphertext: ")
            try:
                decrypted = aes_decrypt_gcm(enc, aes_key)
                print("\nDecrypted:", decrypted.decode())
            except ValueError:
                print("❌ Decryption failed (data tampered)")

        elif choice == "3":
            msg = input("Enter message: ").encode()
            encrypted = rsa_encrypt(msg, rsa_public)
            print("\nEncrypted (base64):", encrypted)

        elif choice == "4":
            enc = input("Enter base64 ciphertext: ")
            decrypted = rsa_decrypt(enc, rsa_private)
            print("\nDecrypted:", decrypted.decode())

        elif choice == "5":
            msg = input("Enter message to sign: ").encode()
            signature = rsa_sign(msg, rsa_private)
            print("\nSignature (base64):", signature)

        elif choice == "6":
            msg = input("Enter original message: ").encode()
            sig = input("Enter base64 signature: ")
            valid = rsa_verify(msg, sig, rsa_public)
            print("\nSignature valid?", valid)

        elif choice == "7":
            data = input("Enter data to hash: ").encode()
            print("\nSHA-256:", sha256_hex(data))

        elif choice == "8":
            data = input("Enter message: ").encode()
            key = get_random_bytes(32)
            print("\nHMAC-SHA256:", hmac_sha256_hex(key, data))
            print("(Random key generated for demo)")

        elif choice == "0":
            print("Exiting...")
            break

        else:
            print("Invalid option. Try again.")

# =========================
# Run
# =========================

if __name__ == "__main__":
    main()

import random
import string
import hashlib
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def get_salt(length):
    alphabet = string.ascii_letters + string.digits
    return ''.join(random.choice(alphabet) for _ in range(length))

def hash_password(password, salt):
    iterations = 10000
    key_length = 64  # 64 bytes for SHA-512
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        iterations=iterations,
        length=key_length,
        salt=salt.encode(),
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_secure_password(password, salt):
    print(f"Password: {password}, Salt: {salt}\n")
    
    # Hashing the password with PBKDF2-HMAC-SHA512
    secure_password = hash_password(password, salt)
    print(f"Secure Password: {secure_password}\n")
    
    # Base64 encode the hashed password
    encoded_secure_password = base64.b64encode(secure_password).decode()
    print(f"Secure Password (Base64): {encoded_secure_password}\n")
    
    return encoded_secure_password

# Example usage:
length_of_salt = 16
password = input("What is your password? ")

generated_salt = get_salt(length_of_salt)
print(f"Generated Salt: {generated_salt}\n")

secure_password = generate_secure_password(password, generated_salt)
print(f"Generated Secure Password: {secure_password}\n")

#Does the Password match

password = input("What is your password? ")

secure_password_validated = generate_secure_password(password, generated_salt)

if secure_password == secure_password_validated:
    print ("That is the correct password.")
else:
    print ("That is the incorrect password.")
print(f"Generated Secure Password: {secure_password}\n")

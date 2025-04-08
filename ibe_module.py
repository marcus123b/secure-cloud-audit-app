from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Step 1: Generate RSA key pair
def generate_keys(identity):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(f"keys/{identity}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(f"keys/{identity}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Keys generated for {identity}")

# Step 2: Encrypt text
def encrypt_text(plain_text, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    encrypted = public_key.encrypt(
        plain_text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Step 3: Encrypt file
def encrypt_file(input_path, output_path, public_key_path):
    with open(input_path, 'r') as f:
        data = f.read()
    encrypted = encrypt_text(data, public_key_path)
    with open(output_path, 'wb') as f:
        f.write(encrypted)
    print(f"Encrypted file saved to: {output_path}")

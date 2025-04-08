from ibe_module import generate_keys, encrypt_file

# Step 1: Generate keys for a user identity
generate_keys("alice@example.com")

# Step 2: Encrypt the sanitized file using Alice's public key
encrypt_file(
    input_path="data/encrypted/sanitized_sample.txt",
    output_path="data/encrypted/ibe_encrypted.bin",
    public_key_path="keys/alice@example.com_public.pem"
)
from abe_module import define_policy, check_access

# Step 3: Define ABE access policy
define_policy("data/encrypted/ibe_encrypted.bin", {
    "role": "Doctor",
    "access_level": "Confidential"
})

# Step 4: Simulate a user trying to access the file
user1 = {"role": "Doctor", "access_level": "Confidential"}       # should be allowed
user2 = {"role": "Nurse", "access_level": "Restricted"}          # should be denied

print("\n[Access Check for User 1]:", "Granted" if check_access(user1, "data/encrypted/ibe_encrypted.bin") else "❌Denied")
print("[Access Check for User 2]:", "Granted" if check_access(user2, "data/encrypted/ibe_encrypted.bin") else "❌ Denied")
from auditor import generate_hash, log_audit

# Step 5: Simulate Integrity Check & Audit Log
file_path = "data/encrypted/ibe_encrypted.bin"
user = "alice@example.com"
access_granted = check_access(user1, file_path)
file_hash = generate_hash(file_path)
integrity_status = "Verified" if file_hash else "Failed"

# Log the access + integrity check
log_audit(file_path, user, access_granted, integrity_status)
from zkp_he_simulation import perform_audit

print("\n[🧠 ZKP + HE Simulation] Running third-party audit...")
zkp_verified = perform_audit("data/encrypted/ibe_encrypted.bin")


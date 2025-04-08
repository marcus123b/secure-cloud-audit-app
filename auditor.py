import hashlib
import json
from datetime import datetime

# Generate hash of file (for integrity check)
def generate_hash(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        return hashlib.sha256(content).hexdigest()
    except FileNotFoundError:
        return None

# Log audit result
def log_audit(file_path, user_identity, status, integrity_status):
    log_entry = {
        "file": file_path,
        "user": user_identity,
        "access_granted": status,
        "integrity_check": integrity_status,
        "timestamp": datetime.now().isoformat()
    }

    with open("audit_logs/audit_log.json", "a") as f:
        json.dump(log_entry, f)
        f.write("\n")
    print(f"Audit logged for {user_identity}")

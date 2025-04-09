import re

# === Generic sanitizer (full redaction) ===
def sanitize_text(text):
    patterns = {
        r"Patient Name: [A-Za-z ]+": "Patient Name: [REDACTED]",
        r"Patient ID: \d+": "Patient ID: [REDACTED]",
        r"Date of Birth: \d{2}/\d{2}/\d{4}": "Date of Birth: [REDACTED]"
    }
    for pattern, replacement in patterns.items():
        text = re.sub(pattern, replacement, text)
    return text

# === Full file redaction ===
def sanitize_file(input_path, output_path):
    with open(input_path, 'r') as file:
        content = file.read()
    sanitized = sanitize_text(content)
    with open(output_path, 'w') as file:
        file.write(sanitized)
    print(f"Sanitized file saved to: {output_path}")

# === Role-specific sanitization ===
def sanitize_for_role(input_path, output_doctor, output_nurse):
    with open(input_path, "r") as f:
        content = f.read()

    # Doctor: full access, no redaction
    doctor_data = content

    # Nurse: only keep name and ID, redact the rest
    name_match = re.search(r"(Patient Name: [A-Za-z ]+)", content)
    id_match = re.search(r"(Patient ID: \d+)", content)

    name_line = name_match.group(0) if name_match else "Patient Name: [REDACTED]"
    id_line = id_match.group(0) if id_match else "Patient ID: [REDACTED]"

    nurse_data = f"{name_line}\n{id_line}\n[Other information hidden for privacy]"

    with open(output_doctor, "w") as f:
        f.write(doctor_data)
    with open(output_nurse, "w") as f:
        f.write(nurse_data)

    print(f"Doctor file saved to: {output_doctor}")
    print(f"Nurse file saved to: {output_nurse}")

import re

def sanitize_text(text):
    patterns = {
        r"Patient Name: [A-Za-z ]+": "Patient Name: [REDACTED]",
        r"Patient ID: \d+": "Patient ID: [REDACTED]",
        r"Date of Birth: \d{2}/\d{2}/\d{4}": "Date of Birth: [REDACTED]"
    }
    for pattern, replacement in patterns.items():
        text = re.sub(pattern, replacement, text)
    return text

def sanitize_file(input_path, output_path):
    with open(input_path, 'r') as file:
        content = file.read()
    sanitized = sanitize_text(content)
    with open(output_path, 'w') as file:
        file.write(sanitized)
    print(f"Sanitized file saved to: {output_path}")
sanitize_file("data/raw/sample.txt", "data/encrypted/sanitized_sample.txt")


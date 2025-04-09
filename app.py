import json
import streamlit as st
from sanitizer import sanitize_file, sanitize_for_role
from ibe_module import generate_keys, encrypt_file
from abe_module import define_policy, check_access
from auditor import generate_hash, log_audit
from zkp_he_simulation import perform_audit
import os
import pandas as pd

st.set_page_config(page_title="Secure Cloud Audit App", layout="centered")
st.title("🔐 Identity-Based Cloud Storage Audit")

# --- Session-safe file tracking ---
if "encrypted_path" not in st.session_state:
    st.session_state.encrypted_path = None
if "identity" not in st.session_state:
    st.session_state.identity = ""

# === Upload Section ===
uploaded = st.file_uploader("📁 Upload a sensitive text file", type=["txt"])

if uploaded:
    input_path = "data/raw/sample_ui.txt"
    output_doctor = "data/encrypted/sanitized_doctor.txt"
    output_nurse = "data/encrypted/sanitized_nurse.txt"
    output_path = "data/encrypted/sanitized_sample_ui.txt"

    with open(input_path, "wb") as f:
        f.write(uploaded.read())
    st.success("✅ File uploaded!")

    # Original sanitize for logging
    sanitize_file(input_path, output_path)
    st.info("Sanitized file created.")

    # Role-based versions
    sanitize_for_role(input_path, output_doctor, output_nurse)

    # Identity input
    st.session_state.identity = st.text_input("Enter user identity (e.g. alice@example.com)", "alice@example.com")

    if st.button("🔑 Generate Keys & Encrypt"):
        generate_keys(st.session_state.identity)
        public_key_path = f"keys/{st.session_state.identity}_public.pem"

        # Encrypt all versions
        encrypt_file(output_path, "data/encrypted/ibe_encrypted_ui.bin", public_key_path)
        encrypt_file(output_doctor, "data/encrypted/doctor_encrypted.bin", public_key_path)
        encrypt_file(output_nurse, "data/encrypted/nurse_encrypted.bin", public_key_path)

        st.session_state.encrypted_path = "data/encrypted/ibe_encrypted_ui.bin"
        st.success("🔐 Files encrypted successfully!")

# === Set Access Policy ===
if st.session_state.encrypted_path:
    st.subheader("🛡️ Define Access Policy")

    col1, col2 = st.columns(2)
    with col1:
        policy_role = st.selectbox("Select Role for Access", ["Doctor", "Nurse", "Admin"])
    with col2:
        policy_level = st.selectbox("Select Access Level", ["Confidential", "Restricted", "Public"])

    if st.button("Set Policy"):
        define_policy(st.session_state.encrypted_path, {"role": policy_role, "access_level": policy_level})
        st.success("✅ Policy attached to encrypted file.")

    # === Access Check ===
    st.subheader("👤 Access Attempt")

    user_role = st.text_input("User Role", "Doctor")
    user_access = st.text_input("Access Level", "Confidential")
    user_attrs = {"role": user_role, "access_level": user_access}

    if st.button("🔍 Check Access"):
        access_result = check_access(user_attrs, st.session_state.encrypted_path)

        if access_result:
            st.success("✅ Access GRANTED — user meets policy requirements.")
        else:
            st.error("❌ Access DENIED — user does not meet policy requirements.")

        # === Audit & Integrity Check ===
        st.subheader("📋 Audit & Integrity Verification")
        zkp_verified = perform_audit(st.session_state.encrypted_path)
        integrity_status = "Verified" if zkp_verified else "Failed"
        log_audit(st.session_state.encrypted_path, st.session_state.identity, access_result, integrity_status)

        if zkp_verified:
            st.success("🔒 Integrity Verified: The file has not been tampered with.")
        else:
            st.error("⚠️ Integrity Check Failed: File may have been altered.")

        # === Conditional File Download ===
        if access_result:
            role = user_role.lower()

            if role == "doctor":
                filepath = "data/encrypted/sanitized_doctor.txt"
                label = "📄 Download Full Medical Record"
            elif role == "nurse":
                filepath = "data/encrypted/sanitized_nurse.txt"
                label = "📄 Download Limited Patient Info"
            else:
                filepath = None

            if filepath and os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    data = f.read()
                st.download_button(label=label, data=data, file_name="patient_info.txt", mime="text/plain")
            else:
                st.warning("⚠️ This role is not authorized to download any file.")

# === Audit Log Table ===
st.subheader("📊 Audit History")

if os.path.exists("audit_logs/audit_log.json"):
    with open("audit_logs/audit_log.json", "r") as f:
        lines = f.readlines()
        entries = [json.loads(line.strip()) for line in lines]

    df = pd.DataFrame(entries)
    st.dataframe(df)

    st.download_button(
        label="⬇️ Download Full Audit Log (.json)",
        data="".join(lines),
        file_name="audit_log.json",
        mime="application/json"
    )
else:
    st.info("ℹ️ No audit log found yet. Run access checks to generate entries.")

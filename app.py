import streamlit as st
from sanitizer import sanitize_file
from ibe_module import generate_keys, encrypt_file
from abe_module import define_policy, check_access
from auditor import generate_hash, log_audit
from zkp_he_simulation import perform_audit
import os

st.title("🔐 Identity-Based Cloud Storage Audit")

# Upload raw file
uploaded = st.file_uploader("📁 Upload a sensitive text file", type=["txt"])

if uploaded:
    input_path = "data/raw/sample_ui.txt"
    output_path = "data/encrypted/sanitized_sample_ui.txt"

    # Save uploaded file
    with open(input_path, "wb") as f:
        f.write(uploaded.read())
    st.success("File uploaded!")

    # Run sanitizer
    sanitize_file(input_path, output_path)
    st.info("Sanitized file created.")

    # Generate keys
    identity = st.text_input("Enter user identity (e.g. alice@example.com)", "alice@example.com")
    if st.button("🔑 Generate Keys & Encrypt"):
        generate_keys(identity)
        public_key_path = f"keys/{identity}_public.pem"
        encrypted_path = "data/encrypted/ibe_encrypted_ui.bin"
        encrypt_file(output_path, encrypted_path, public_key_path)
        st.success("File encrypted using IBE!")

        # ABE Policy Setup
        st.subheader("🛡️ Access Policy")
        role = st.selectbox("Select Role", ["Doctor", "Nurse", "Admin"])
        access_level = st.selectbox("Access Level", ["Confidential", "Restricted", "Public"])
        define_policy(encrypted_path, {"role": role, "access_level": access_level})
        st.success("Policy attached to encrypted file.")

        # Simulate Access
        st.subheader("👤 Access Check")
        user_role = st.text_input("User Role", "Doctor")
        user_access = st.text_input("Access Level", "Confidential")
        user_attr = {"role": user_role, "access_level": user_access}

        if check_access(user_attr, encrypted_path):
            st.success("✅ Access GRANTED")
        else:
            st.error("❌ Access DENIED")

        # Audit + ZKP
        st.subheader("🔍 Audit & Integrity Check")
        zkp_result = perform_audit(encrypted_path)
        integrity_status = "Verified" if zkp_result else "Failed"
        log_audit(encrypted_path, identity, True, integrity_status)
        st.info(f"Audit Result: {integrity_status}")

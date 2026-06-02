from ch512 import CH512
import json
import os

# Initialize cipher
cipher = CH512()

print("="*50)
print("CH512 - CrashHybrid Cipher - Example")
print("="*50)

# ============================================================
# EXAMPLE 1: ENCRYPT A STRING
# ============================================================
print("\n[1] Encrypt a string")

password = "my_secure_password_2024"
plaintext = "Secret message for the shelter"

ciphertext = cipher.encrypt(plaintext, password)
print(f"Password: {password}")
print(f"Plaintext: {plaintext}")
print(f"Ciphertext (hex): {ciphertext.hex()[:64]}...")

decrypted = cipher.decrypt(ciphertext, password)
print(f"Decrypted: {decrypted.decode()}")

# ============================================================
# EXAMPLE 2: ENCRYPT STRUCTURED DATA (JSON)
# ============================================================
print("\n[2] Encrypt structured JSON data")

shelter_data = {
    "coordinates": "45.1234, 7.5678",
    "access_code": "X7K9P2",
    "supplies": ["water", "food", "medicines"],
    "room_location": "room_B_3",
    "radio_frequency": "146.520 MHz"
}

# Convert to JSON
json_string = json.dumps(shelter_data, indent=2)
print(f"Original data: {json_string}")

# Encrypt
ciphertext_json = cipher.encrypt(json_string, password)

# Save to file
with open("secret_shelter.ch512", "wb") as f:
    f.write(ciphertext_json)
print(f"Encrypted file saved: secret_shelter.ch512 ({len(ciphertext_json)} bytes)")

# Read and decrypt
with open("secret_shelter.ch512", "rb") as f:
    encrypted_data = f.read()

decrypted_json = cipher.decrypt(encrypted_data, password)
recovered_data = json.loads(decrypted_json.decode())
print(f"Recovered data: {recovered_data['access_code']}")

# ============================================================
# EXAMPLE 3: ERROR HANDLING (WRONG PASSWORD)
# ============================================================
print("\n[3] Error handling - wrong password")

try:
    result = cipher.decrypt(ciphertext, "wrong_password")
    print("ERROR: should have failed!")
except ValueError as e:
    print(f"Success: decryption failed as expected")
    print(f"Error: {e}")

# ============================================================
# EXAMPLE 4: ENCRYPT A FILE
# ============================================================
print("\n[4] Encrypt a file")

# Create a sample file
with open("test_document.txt", "w") as f:
    f.write("Sensitive document content.\n" * 10)

# Encrypt the file
cipher.encrypt_file("test_document.txt", "test_document.enc", password)
print("File encrypted: test_document.txt -> test_document.enc")

# Decrypt the file
cipher.decrypt_file("test_document.enc", "test_document.dec", password)
print("File decrypted: test_document.enc -> test_document.dec")

# Verify it matches the original
with open("test_document.txt", "r") as f1, open("test_document.dec", "r") as f2:
    if f1.read() == f2.read():
        print("VERIFICATION OK: decrypted file matches original")

# ============================================================
# EXAMPLE 5: ENCRYPT BINARY DATA (E.G. IMAGE)
# ============================================================
print("\n[5] Encrypt binary data")

# Create random binary data
binary_data = os.urandom(1024)
print(f"Binary data: {len(binary_data)} bytes")

cipher_bin = cipher.encrypt(binary_data, password)
print(f"Binary ciphertext: {len(cipher_bin)} bytes")

decrypted_bin = cipher.decrypt(cipher_bin, password)
if decrypted_bin == binary_data:
    print("VERIFICATION OK: binary data recovered correctly")

# ============================================================
# EXAMPLE 6: WORKING WITH LARGE FILES (STREAMING)
# ============================================================
print("\n[6] Encrypt large file (1024 MB simulated)")

# Note: for very large files, use encrypt_file/decrypt_file
# which handle streaming automatically

print("For large files (GB) use:")
print("  cipher.encrypt_file('large.dat', 'large.enc', password)")
print("  cipher.decrypt_file('large.enc', 'large.dec', password)")

print("\n" + "="*50)
print("All examples completed successfully!")
print("="*50)

# Clean up temporary files
os.remove("test_document.txt")
os.remove("test_document.enc")
os.remove("test_document.dec")
os.remove("secret_shelter.ch512")
import hashlib
from Crypto.Cipher import AES
import binascii

# 🔹 Replace with your values
password = b"Password"
salt = binascii.unhexlify("salt in hex format")
iterations = enter your iteration count  # Example: 200000
encrypted_master_key = binascii.unhexlify("publicKey in hex format")

# **STEP 1: Custom SHA-512 Key Derivation**
derived_key = password + salt
for i in range(iterations):
    derived_key = hashlib.sha512(derived_key).digest()

# Extract AES Key (first 32 bytes)
aes_key = derived_key[:32]

# **STEP 2: AES Decryption (AES-256-CBC)**
aes_iv = encrypted_master_key[:16]  # First 16 bytes are IV
encrypted_data = encrypted_master_key

if len(encrypted_data) != 48:
    raise ValueError(f"🚨 ERROR: Encrypted data length incorrect! Expected 48 bytes but got {len(encrypted_data)}")

# ✅ Decrypt all 48 bytes now
cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
raw_decrypted_data = cipher.decrypt(encrypted_data)

# ✅ Print raw decrypted data
print("\n🔍 Raw Decrypted Data (Hex):", binascii.hexlify(raw_decrypted_data).decode())
print("🔹 Raw Decrypted Data Length:", len(raw_decrypted_data), "bytes")

# **STEP 3: Validate PKCS7 Padding**
padding_len = raw_decrypted_data[-1]  # The last byte gives padding length
if all(b == padding_len for b in raw_decrypted_data[-padding_len:]):  # Check if all last bytes match the padding value
    print("\n✅ Valid PKCS7 Padding Found! Stripping it...")
    decrypted_master_key = raw_decrypted_data[:-padding_len]  # Strip padding
else:
    print("\n🚨 WARNING: Padding check failed! Using full decrypted data.")
    decrypted_master_key = raw_decrypted_data  # Keep full data for debugging

# ✅ Final Master Key Output
print("\n✅ Final Master Key (Hex):", binascii.hexlify(decrypted_master_key).decode())
print("🔹 Final Master Key Length:", len(decrypted_master_key), "bytes")

# **Ensure Correct Length**
if len(decrypted_master_key) != 32:
    print("\n🚨 ERROR: Final Master Key length incorrect! Expected 32 bytes but got", len(decrypted_master_key))
else:
    print("\n✅ Decryption Successful! Master Key is correct.")

## Use resulting 32 byte decrypted master key as aes key and a double sha256 of the public key as the iv to decrypt encrypted private keys

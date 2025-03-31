import hashlib
import binascii
import pyaes

password = b"password"
salt = binascii.unhexlify("salt in hex")
iterations = iteration count  # Example: 200000
encrypted_master_key = binascii.unhexlify("encrypted master key")

derived_key = password + salt
for i in range(iterations):
    derived_key = hashlib.sha512(derived_key).digest()

aes_key = derived_key[:32]

aes_iv = derived_key[:16]  # First 16 bytes are IV
encrypted_data = encrypted_master_key

decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(aes_key, aes_iv))
decryptedData = decrypter.feed(encrypted_master_key)
decryptedData += decrypter.feed()

print(binascii.hexlify(decryptedData))

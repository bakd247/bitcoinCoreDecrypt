import hashlib
import binascii
import pyaes

password = b"Maryjane1"
salt = binascii.unhexlify("ddb003131dc689c1")
iterations = 28412  # Example: 200000
encrypted_master_key = binascii.unhexlify("37b3ee0906a2f34aac4c56c9fd5d0bd9277e2feb760615159ea039fc48bea3f27e903be93c3dfaedba4b556df4f698ba")

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

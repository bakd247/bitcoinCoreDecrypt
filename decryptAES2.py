import hashlib
import binascii
import pyaes

password = b"passphrase"
salt = binascii.unhexlify("salt in hex")
iterations = iteration count  # Example: 200000
encrypted_master_key = binascii.unhexlify("encrypted master key")

derived_key = password + salt
for i in range(iterations):
    derived_key = hashlib.sha512(derived_key).digest()

aes_key = derived_key[:32]

aes_iv = derived_key[32:32+16]
encrypted_data = encrypted_master_key

decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(aes_key, aes_iv))
decryptedData = decrypter.feed(encrypted_master_key)
decryptedData += decrypter.feed()

print(binascii.hexlify(decryptedData))

publicKey = binascii.unhexlify("public key")
encrypted_priv_Key = (binascii.unhexlify("encrypted private key"))
master_Key = decryptedData[0:32]
newIV = (hashlib.sha256(hashlib.sha256(publicKey).digest()).digest())[0:16]

decrypter2 = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(master_Key, newIV))
decryptedData2 = decrypter2.feed(encrypted_priv_Key)
decryptedData2 += decrypter2.feed()

print(binascii.hexlify(decryptedData2))

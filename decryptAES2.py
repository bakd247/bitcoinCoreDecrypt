import hashlib
import binascii
from Crypto.Cipher import AES

def setMasterKey(vKeyData, vSalt, nDerivIterations, nDerivationMethod):
    if nDerivationMethod != 0:
        nDerivationMethod = 0
    data = bytes(((vKeyData) + (vSalt)), 'ascii')
    for i in range(nDerivIterations):
        data = hashlib.sha512(data).digest()
    key = binascii.hexlify(data[0:32])
    
    IV= binascii.hexlify(data[32:32+16])
    
    return(key, IV)

passphrase = input("Please Enter your passphrase:")
salt = input("Please Enter the hexidecimal Salt Value:")
iterations = int((input("Please Enter the Number of Iterations for the hashing Function:")), 10)
method = input("Please enter the numerical Derivation Method:")

masterKey = (setMasterKey(passphrase, salt, iterations, method))
print(masterKey)

keyBeenSet = binascii.unhexlify(masterKey[0])
ivBeenSet = binascii.unhexlify(masterKey[1])

def Encrypt(data):
    return AES.new(keyBeenSet,AES.MODE_CBC,ivBeenSet).encrypt(data)
def Decrypt(data):
    return AES.new(keyBeenSet,AES.MODE_CBC,ivBeenSet).decrypt(data)[0:32]

# Need to append_PKCS7_padding to data prior to encryption

encMaster= (binascii.hexlify(Encrypt(keyBeenSet)))

print("This should match your EncryptedMaster Key:", encMaster)

encryptedMasterKey = bytes(input("If your wallet contains the above key...Please enter the Encrypted Master key from your wallet in hexidecimal format to confirm:"), 'ascii')

newKeyToShow = (binascii.hexlify(Decrypt(encryptedMasterKey)))
newKey = binascii.unhexlify(newKeyToShow)
setNewIV = bytes(input("Please Enter the Public key belonging to the encrypted Private Key your trying to recover:"), 'ascii')
newIV = (hashlib.sha256(hashlib.sha256(setNewIV).digest()).digest())[0:16]
newIVToShow = binascii.hexlify(newIV)
print("This is Your New Key:", newKeyToShow)
print("This is Your New IV:", newIVToShow)
newSetIV = binascii.unhexlify(newIVToShow)
encryptedPrivateKey = bytes(input("Please Enter Your Encrypted Private Key in Hecidecimal format:"), 'ascii')

def decryptEncPriv(data):
    return AES.new(newKey,AES.MODE_CBC,newIV).decrypt(encryptedPrivateKey)[0:32]

print(binascii.hexlify(decryptEncPriv(encryptedPrivateKey)))


##Example Code:

##Above is not working...change to openssl evp bytes_To_key method to ensure accuracy

# def SetKeyFromPassphrase(self, vKeyData, vSalt, nDerivIterations, nDerivationMethod):
#     if nDerivationMethod != 0:
#         return 0
#     strKeyData = ctypes.create_string_buffer (vKeyData)
#     chSalt = ctypes.create_string_buffer (vSalt)
#     return ssl.EVP_BytesToKey(ssl.EVP_aes_256_cbc(), ssl.EVP_sha512(), chSalt, strKeyData,
#         len(vKeyData), nDerivIterations, ctypes.byref(self.chKey), ctypes.byref(self.chIV))

# def SetKey(self, key):
#     self.chKey = ctypes.create_string_buffer(key)

# def SetIV(self, iv):
#     self.chIV = ctypes.create_string_buffer(iv)

# def Encrypt(self, data):
#     buf = ctypes.create_string_buffer(len(data) + 16)
#     written = ctypes.c_int(0)
#     final = ctypes.c_int(0)
#     ctx = ssl.EVP_CIPHER_CTX_new()
#     ssl.EVP_CIPHER_CTX_init(ctx)
#     ssl.EVP_EncryptInit_ex(ctx, ssl.EVP_aes_256_cbc(), None, self.chKey, self.chIV)
#     ssl.EVP_EncryptUpdate(ctx, buf, ctypes.byref(written), data, len(data))
#     output = buf.raw[:written.value]
#     ssl.EVP_EncryptFinal_ex(ctx, buf, ctypes.byref(final))
#     output += buf.raw[:final.value]
#     return output

# def Decrypt(self, data):
#     buf = ctypes.create_string_buffer(len(data) + 16)
#     written = ctypes.c_int(0)
#     final = ctypes.c_int(0)
#     ctx = ssl.EVP_CIPHER_CTX_new()
#     ssl.EVP_CIPHER_CTX_init(ctx)
#     ssl.EVP_DecryptInit_ex(ctx, ssl.EVP_aes_256_cbc(), None, self.chKey, self.chIV)
#     ssl.EVP_DecryptUpdate(ctx, buf, ctypes.byref(written), data, len(data))
#     output = buf.raw[:written.value]
#     ssl.EVP_DecryptFinal_ex(ctx, buf, ctypes.byref(final))
#     output += buf.raw[:final.value]
#     return output
import hashlib
import binascii
from Crypto.Cipher import AES

def setMasterKey(vKeyData, vSalt, nDerivIterations, nDerivationMethod):
    if nDerivationMethod != 0:
        nDerivationMethod = 0
    data = bytes(((vKeyData) + (vSalt)), 'ascii')
    for i in range(nDerivIterations):
        data = hashlib.sha512(data).digest()
    key = binascii.hexlify(data[0:32])
    
    IV= binascii.hexlify(data[32:32+16])
    
    return(key, IV)

passphrase = input("Please Enter your passphrase:")
salt = input("Please Enter the hexidecimal Salt Value:")
iterations = int((input("Please Enter the Number of Iterations for the hashing Function:")), 10)
method = input("Please enter the numerical Derivation Method:")

masterKey = (setMasterKey(passphrase, salt, iterations, method))
print(masterKey)

keyBeenSet = binascii.unhexlify(masterKey[0])
ivBeenSet = binascii.unhexlify(masterKey[1])

def Encrypt(data):
    return AES.new(keyBeenSet,AES.MODE_CBC,ivBeenSet).encrypt(data)
def Decrypt(data):
    return AES.new(keyBeenSet,AES.MODE_CBC,ivBeenSet).decrypt(data)[0:32]

# Need to append_PKCS7_padding to data prior to encryption

encMaster= (binascii.hexlify(Encrypt(keyBeenSet)))

print("This should match your EncryptedMaster Key:", encMaster)

encryptedMasterKey = bytes(input("If your wallet contains the above key...Please enter the Encrypted Master key from your wallet in hexidecimal format to confirm:"), 'ascii')

newKeyToShow = (binascii.hexlify(Decrypt(encryptedMasterKey)))
newKey = binascii.unhexlify(newKeyToShow)
setNewIV = bytes(input("Please Enter the Public key belonging to the encrypted Private Key your trying to recover:"), 'ascii')
newIV = (hashlib.sha256(hashlib.sha256(setNewIV).digest()).digest())[0:16]
newIVToShow = binascii.hexlify(newIV)
print("This is Your New Key:", newKeyToShow)
print("This is Your New IV:", newIVToShow)
newSetIV = binascii.unhexlify(newIVToShow)
encryptedPrivateKey = bytes(input("Please Enter Your Encrypted Private Key in Hecidecimal format:"), 'ascii')

def decryptEncPriv(data):
    return AES.new(newKey,AES.MODE_CBC,newIV).decrypt(encryptedPrivateKey)[0:32]

print(binascii.hexlify(decryptEncPriv(encryptedPrivateKey)))


##Example Code:

##Above is not working...change to openssl evp bytes_To_key method to ensure accuracy

# def SetKeyFromPassphrase(self, vKeyData, vSalt, nDerivIterations, nDerivationMethod):
#     if nDerivationMethod != 0:
#         return 0
#     strKeyData = ctypes.create_string_buffer (vKeyData)
#     chSalt = ctypes.create_string_buffer (vSalt)
#     return ssl.EVP_BytesToKey(ssl.EVP_aes_256_cbc(), ssl.EVP_sha512(), chSalt, strKeyData,
#         len(vKeyData), nDerivIterations, ctypes.byref(self.chKey), ctypes.byref(self.chIV))

# def SetKey(self, key):
#     self.chKey = ctypes.create_string_buffer(key)

# def SetIV(self, iv):
#     self.chIV = ctypes.create_string_buffer(iv)

# def Encrypt(self, data):
#     buf = ctypes.create_string_buffer(len(data) + 16)
#     written = ctypes.c_int(0)
#     final = ctypes.c_int(0)
#     ctx = ssl.EVP_CIPHER_CTX_new()
#     ssl.EVP_CIPHER_CTX_init(ctx)
#     ssl.EVP_EncryptInit_ex(ctx, ssl.EVP_aes_256_cbc(), None, self.chKey, self.chIV)
#     ssl.EVP_EncryptUpdate(ctx, buf, ctypes.byref(written), data, len(data))
#     output = buf.raw[:written.value]
#     ssl.EVP_EncryptFinal_ex(ctx, buf, ctypes.byref(final))
#     output += buf.raw[:final.value]
#     return output

# def Decrypt(self, data):
#     buf = ctypes.create_string_buffer(len(data) + 16)
#     written = ctypes.c_int(0)
#     final = ctypes.c_int(0)
#     ctx = ssl.EVP_CIPHER_CTX_new()
#     ssl.EVP_CIPHER_CTX_init(ctx)
#     ssl.EVP_DecryptInit_ex(ctx, ssl.EVP_aes_256_cbc(), None, self.chKey, self.chIV)
#     ssl.EVP_DecryptUpdate(ctx, buf, ctypes.byref(written), data, len(data))
#     output = buf.raw[:written.value]
#     ssl.EVP_DecryptFinal_ex(ctx, buf, ctypes.byref(final))
#     output += buf.raw[:final.value]
#     return output

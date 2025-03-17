import hashlib
import binascii
from Crypto.Cipher import AES

##need to def SetKey() here...then implement below
## keys and ivs need to have "ord()" operator inserted correctly!!!
##below is an example as seen in pywallet
# def ordsix(data):
#     return ord(data)
# def SetKey(self, key):
#     self.chKey = [ordsix(i) for i in key]

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

# def SetIV(self, iv):
#     self.chIV = [ordsix(i) for i in iv]

# def SetKeyFromPassphrase(self, vKeyData, vSalt, nDerivIterations, nDerivationMethod):
#     if nDerivationMethod != 0:
#         return 0
#     data = str_to_bytes(vKeyData) + vSalt
#     for i in xrange(nDerivIterations):
#         data = hashlib.sha512(data).digest()
#     self.SetKey(data[0:32])
#     self.SetIV(data[32:32+16])
#     return len(data)

# def SetKey(self, key):
#     self.chKey = key

# def SetIV(self, iv):
#     self.chIV = iv[0:16]

# def Encrypt(self, data):
#     return AES.new(self.chKey,AES.MODE_CBC,self.chIV).encrypt(append_PKCS7_padding(data))

# def Decrypt(self, data):
#     return AES.new(self.chKey,AES.MODE_CBC,self.chIV).decrypt(data)[0:32]

# another implementation
# if 'mkey' in json_db.keys() and 'salt' in json_db['mkey']:
# 		crypted = True
# if crypted:
#     if passphrase:
#         cry_master = binascii.unhexlify(json_db['mkey']['encrypted_key'])
#         cry_salt   = binascii.unhexlify(json_db['mkey']['salt'])
#         cry_rounds = json_db['mkey']['nDerivationIterations']
#         cry_method = json_db['mkey']['nDerivationMethod']

#         crypter.SetKeyFromPassphrase(passphrase, cry_salt, cry_rounds, cry_method)
# #			if verbose:
# #				print("Import with", passphrase, "", binascii.hexlify(cry_master), "", binascii.hexlify(cry_salt))
#         masterkey = crypter.Decrypt(cry_master)
#         crypter.SetKey(masterkey)
#         crypter.SetIV(Hash(public_key))
#         e = crypter.Encrypt(secret)
#         ck_epk=e

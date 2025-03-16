import hashlib
import binascii
from Crypto.Cipher import AES

##need to def SetKey() here...then implement below
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

## keys and ivs need to have "ord()" operator inserted correctly!!!
##below is an example as seen in pywallet
# def ordsix(data):
#     return ord(data)
# def SetKey(self, key):
#     self.chKey = [ordsix(i) for i in key]

# def SetIV(self, iv):
#     self.chIV = [ordsix(i) for i in iv]

##Not sure if input is converted to bytes correctly or not either if using ord()

##May need to set to encrypt first in order to get correct encrypted master key

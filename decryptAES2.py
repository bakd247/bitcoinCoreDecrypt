import hashlib
import binascii
from Crypto.Cipher import AES
def setMasterKey(vKeyData, vSalt, nDerivIterations, nDerivationMethod):
    if nDerivationMethod != 0:
        nDerivationMethod = 0
    data = bytes(((vKeyData) + (vSalt)), 'ascii')
    for i in range(nDerivIterations):
        data = hashlib.sha512(data).digest()
    key = data[0:32]
    IV= data[32:32+16]
    key =  binascii.hexlify(key)
    IV =  binascii.hexlify(IV)
    return(key, IV)

passphrase = input("Please Enter your passphrase:")
salt = input("Please Enter the hexidecimal Salt Value:")
iterations = int((input("Please Enter the Number of Iterations for the hashing Function:")), 10)
method = input("Please enter the numerical Derivation Method:")

masterKey = (setMasterKey(passphrase, salt, iterations, method))
print(masterKey)

keyBeenSet = binascii.unhexlify(masterKey[0])
ivBeenSet = binascii.unhexlify(masterKey[1])

encryptedMasterKey = bytes(input("Please enter the Encrypted Master key in hexidecimal format:"), 'ascii')

def Decrypt(data):
    return AES.new(keyBeenSet,AES.MODE_CBC,ivBeenSet).decrypt(data)[0:32]

newKeyToShow = (binascii.hexlify(Decrypt(encryptedMasterKey)))
newKey = binascii.unhexlify(newKeyToShow)
setNewIV = bytes(input("Please Enter the encrypted Public key belonging to the encrypted Private Key your trying to recover:"), 'ascii')
newIV = (hashlib.sha256(hashlib.sha256(setNewIV).digest()).digest())[0:16]
newIVToShow = binascii.hexlify(newIV)
print("This is Your New Key:", newKeyToShow)
print("This is Your New IV:", newIVToShow)
newSetIV = binascii.unhexlify(newIVToShow)
encryptedPrivateKey = bytes(input("Please Enter Your Encrypted Private Key in Hecidecimal format:"), 'ascii')

def decryptEncPriv(data):
    return AES.new(newKey,AES.MODE_CBC,newIV).decrypt(encryptedPrivateKey)[0:32]

print(binascii.hexlify(decryptEncPriv(encryptedPrivateKey)))
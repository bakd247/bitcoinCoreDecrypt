This Program is intended to decrpyt encrypted Private Keys found in Bitcoin Core and like Wallets that use AES-256-CBC specifically.
Note: it seems to only work on python version 3.10.8 and earlier as 3.11 and up seems to not be able to find the "Crypto" library

The current code will decrypt a master encrypted key using a password, salt and iteration count. This decrypted key is then used along with a double sha256 of a pubic key to decrypt private keys within Core wallets.
Private Key decrypt is currently under development and will be available soon.

This Program is intended to decrpyt encrypted Private Keys found in Bitcoin Core and like Wallets that use AES-256-CBC specifically.
This version works with python 3...
The current code will decrypt a master encrypted key using a password, salt and iteration count. This decrypted key is then used along with a double sha256 of a pubic key to decrypt private keys within Core wallets.
Private Key decrypt is currently under development and will be available soon.

This Program is intended to decrpyt encrypted Private Keys found in Bitcoin Core and like Wallets that use AES-256-CBC specifically.
Note: it seems to only work on python version 3.10.8 and earlier as 3.11 and up seems to not be able to find the "Crypto" library


Currently this is not working correctly as the AES keys need to be set as little endian encoding...will get time for this tommorow

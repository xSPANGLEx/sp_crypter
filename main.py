'''
Created on 2016/11/04

@author: xSPANGLEx
'''
from sp_crypto import sp_crypto
import os
import getpass

if __name__ == '__main__':
    filepath = raw_input("path>>>")
    key = getpass.getpass("Password:")
    crypter = sp_crypto.SP_Crypto(key)
    cmd = raw_input("cmd>>>")
    if cmd == "encrypt":
        crypter.encrypt(open(filepath,"rb"))
    elif cmd == "decrypt":
        crypter.decrypt(open(filepath,"rb"))

'''
Created on 2016/11/04

@author: xSPANGLEx
'''
import hashlib
from Crypto.Cipher import AES
import base64
import os

class SP_Crypto(object):
    '''
    classdocs
    '''

    def __init__(self, key):
        '''
        Constructor
        '''
        self.firstSecretKey = hashlib.sha256(key).digest()
        self.firstIV = hashlib.md5(key).digest()
        self.secondSecretKey = hashlib.sha256(self.firstIV).digest()
        self.secondIV = hashlib.md5(self.firstSecretKey).digest()
        self.delimiter = "\\"
        BS = 16
        self.pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        self.unpad = lambda s : s[0:-ord(s[-1])]

    def firstEncrypt(self,plain_stream):
        firstAESenc = AES.new(self.firstSecretKey,AES.MODE_CBC,self.firstIV)
        plain_stream = self.pad(plain_stream)
        encrypt_stream = firstAESenc.encrypt(plain_stream)
        return encrypt_stream

    def secondEncrypt(self,plain_stream):
        secondAESenc = AES.new(self.secondSecretKey,AES.MODE_CBC,self.secondIV)
        plain_stream = self.pad(plain_stream)
        encrypt_stream = secondAESenc.encrypt(plain_stream)
        encrypt_stream = base64.b64encode(encrypt_stream)
        return encrypt_stream

    def firstDecrypt(self,encrypt_stream):
        firstAESdec = AES.new(self.secondSecretKey,AES.MODE_CBC,self.secondIV)
        encrypt_stream = base64.b64decode(encrypt_stream)
        decrypt_stream = firstAESdec.decrypt(encrypt_stream)
        decrypt_stream = self.unpad(decrypt_stream)
        return decrypt_stream

    def secondDecrypt(self,encrypt_stream):
        secondAESdec = AES.new(self.firstSecretKey,AES.MODE_CBC,self.firstIV)
        decrypt_stream = secondAESdec.decrypt(encrypt_stream)
        decrypt_stream = self.unpad(decrypt_stream)
        return decrypt_stream

    def encrypt(self,fp):
        encryptFilePath = fp.name
        encryptFilePath = os.path.abspath(encryptFilePath)
        encryptFilePath = encryptFilePath + ".spenc"
        if os.path.exists(encryptFilePath):
            return 1
        fw = open(encryptFilePath,"ab")
        while 1:
            stream = fp.read(10485760)
            if stream == "":
                break
            encStream = self.firstEncrypt(stream)
            encStream = self.secondEncrypt(encStream)
            fw.write(encStream + self.delimiter)
        fw.close()

    def decrypt(self,fp):
        decryptFilePath = fp.name
        decryptFilePath = os.path.abspath(decryptFilePath)
        decryptFilePath = decryptFilePath.split(".spenc")[0]
        if os.path.exists(decryptFilePath):
            return 1
        fw = open(decryptFilePath,"ab")
        afterStream = ""
        tmpStream = ""
        while 1:
            stream = fp.read(5242880)
            if stream == "":
                if afterStream != "":
                    tmpStream = afterStream + tmpStream
                    decStream = self.firstDecrypt(tmpStream)
                    decStream = self.secondDecrypt(decStream)
                    fw.write(decStream)
                break
            stream = stream.split("\\")
            if len(stream) == 1:
                tmpStream = tmpStream + stream[0]
            else:
                tmpStream = afterStream + tmpStream + stream[0]
                decStream = self.firstDecrypt(tmpStream)
                decStream = self.secondDecrypt(decStream)
                fw.write(decStream)
                afterStream = stream[1]
                tmpStream = ""
        fw.close()

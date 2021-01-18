import hashlib
import math
import os
import sys
from Crypto.Cipher import AES


class Generator:

    IV_SIZE = 16    # 128 bit, fixed for the AES algorithm
    KEY_SIZE = 32   # 256 bit meaning AES-256, can also be 128 or 192 bits
    SALT_SIZE = 16  # This size is arbitrary
    salt=b''
    iv=[]
    derived=b''
    key=b''
    def __init__(self):
       self.salt = os.urandom(self.SALT_SIZE)
    def anahtarYap(self,password):
        
        self.derived = hashlib.pbkdf2_hmac('sha256', password, self.salt, 100000,dklen=self.IV_SIZE + self.KEY_SIZE)
        self.iv = self.derived[0:self.IV_SIZE]
        self.key = self.derived[self.IV_SIZE:]
        return self.key

    def sifrele(self,key,text):
        return self.salt + AES.new(key, AES.MODE_CFB, self.iv).encrypt(text)

    def coz(self,sifreliBilgi,key):
        return AES.new(key, AES.MODE_CFB, self.iv).decrypt(sifreliBilgi[self.SALT_SIZE:])

a=Generator()
anahtar=a.anahtarYap(b'ROOT')#şifre ascıı karakterlerinden oluşmalı türkçe karakter olmamalı
bilgi = a.sifrele(anahtar,b"textimiz")
bilgi2 = a.sifrele(anahtar,b"deli")
print(anahtar)
print(a.coz(bilgi2,anahtar))

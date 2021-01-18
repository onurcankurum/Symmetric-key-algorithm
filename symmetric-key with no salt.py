from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
def sifrele(msg,parola):#parola 16 bytes olmalı
    b=bytes(msg,'ascii')
    cipher = AES.new(pad(parola.encode("utf8"),32), AES.MODE_ECB)
    msg =cipher.encrypt(pad(b, 32))
    return msg.hex()
  
def coz(msg,parola):
    try:
        msg = bytes.fromhex(msg)
        decipher = AES.new(pad(parola.encode("utf8"),32), AES.MODE_ECB)
        msg=decipher.decrypt(msg)
        return unpad(msg,32).decode("utf-8")
    except ValueError:
        print("\n\n\n !!!şifre yanlış!!!\n\n")
        return "şifreyi görmek için doğru parolayı girin"




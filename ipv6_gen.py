# ipv6_gen.py
# -*- coding: utf-8 -*-

from rsa import PublicKey, common, transform, core
import rsa

# 生成公钥和私钥
def create_keys():  
    (pubkey, privkey) = rsa.newkeys(1024)
    pub = pubkey.save_pkcs1()
    with open('public.pem','wb+')as f:
        f.write(pub)
    print "public key:",pub
 
    pri = privkey.save_pkcs1()
    with open('private.pem','wb+')as f:
        f.write(pri)
    print "private key:",pri

# 用公钥加密
def encrypt_with_pub():  
    with open('public.pem', 'rb') as publickfile:
        p = publickfile.read()
    pubkey = rsa.PublicKey.load_pkcs1(p)
    original_text = 'have a good time'.encode('utf8')
    crypt_text = rsa.encrypt(original_text, pubkey)
    print(crypt_text)
    return crypt_text 

# 用私钥解密
def decrypt_with_pri(crypt_text):  
    with open('private.pem', 'rb') as privatefile:
        p = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(p)
    lase_text = rsa.decrypt(crypt_text, privkey).decode()  
    print(lase_text)

if __name__ == "__main__":
    create_keys()
    crypt_text = encrypt_with_pub()
    lase_text =  decrypt_with_pri(crypt_text)
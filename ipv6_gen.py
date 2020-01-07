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
def encrypt_with_pub(original_text):  
    with open('public.pem', 'rb') as publickfile:
        p = publickfile.read()
    pubkey = rsa.PublicKey.load_pkcs1(p)
    crypt_text = rsa.encrypt(original_text, pubkey)
    return crypt_text 

# 用私钥加密
def encrypt_with_pri(original_text):
    with open('private.pem', 'rb') as privatefile:
        p = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(p)
    crypt_text = rsa.encrypt(original_text, privkey)
    return crypt_text

# 用私钥解密
def decrypt_with_pri(crypt_text):  
    with open('private.pem', 'rb') as privatefile:
        p = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(p)
    original_text = rsa.decrypt(crypt_text, privkey).decode()  
    return original_text

# 用公钥解密
def decrypt_with_pub(crypt_text):
    with open('public.pem', 'rb') as publickfile:
        p = publickfile.read()
    pubkey = rsa.PublicKey.load_pkcs1(p)
    original_text = rsa.decrypt(crypt_text, pubkey).decode()
    return original_text

if __name__ == "__main__":
    create_keys()
    crypt_text = encrypt_with_pub("hello world")
    original_text =  decrypt_with_pri(crypt_text)
    print original_text
    crypt_text_pri = encrypt_with_pri("private")
    original_text_pub = decrypt_with_pub(crypt_text_pri)
    print original_text_pub

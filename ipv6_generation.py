# -*- coding: UTF-8 -*-
# ! /usr/bin/env python
import base64
import rsa
from rsa import common
import random


# 使用 rsa库进行RSA签名和加解密
class RsaUtil(object):
    PUBLIC_KEY_PATH = 'public.pem'  # 公钥
    PRIVATE_KEY_PATH = 'private.pem'  # 私钥

    # 初始化key
    def __init__(self,
                 pub_file=PUBLIC_KEY_PATH,
                 pri_file=PRIVATE_KEY_PATH):

        self.create_keys()
        with open('public.pem', 'rb') as publickfile:
            pub = publickfile.read()
        self.public_key = rsa.PublicKey.load_pkcs1(pub)

        with open('private.pem', 'rb') as privatefile:
            pri = privatefile.read()
        self.private_key = rsa.PrivateKey.load_pkcs1(pri)

        #if pub_file:
        #    self.public_key = rsa.PublicKey.load_pkcs1_openssl_pem(open(pub_file).read())
        #if pri_file:
        #    self.private_key = rsa.PrivateKey.load_pkcs1(open(pri_file).read())
    
    # 生成公钥和私钥
    def create_keys(self):  
        (pubkey, privkey) = rsa.newkeys(1024)
        pub = pubkey.save_pkcs1()
        with open('public.pem','wb+')as f:
            f.write(pub)
        print "public key:",pub
 
        pri = privkey.save_pkcs1()
        with open('private.pem','wb+')as f:
            f.write(pri)
        print "private key:",pri

    def get_max_length(self, rsa_key, encrypt=True):
        """加密内容过长时 需要分段加密 换算每一段的长度.
            :param rsa_key: 钥匙.
            :param encrypt: 是否是加密.
        """
        blocksize = common.byte_size(rsa_key.n)
        reserve_size = 11  # 预留位为11
        if not encrypt:  # 解密时不需要考虑预留位
            reserve_size = 0
        maxlength = blocksize - reserve_size
        return maxlength

    # 公钥加密
    def encrypt_by_public_key(self, message):
        """使用公钥加密.
            :param message: 需要加密的内容.
            加密之后需要对接过进行base64转码
        """
        encrypt_result = b''
        max_length = self.get_max_length(self.public_key)
        while message:
            input = message[:max_length]
            message = message[max_length:]
            out = rsa.encrypt(input, self.public_key)
            encrypt_result += out
        encrypt_result = base64.b64encode(encrypt_result)
        return encrypt_result

    # 私钥解密
    def decrypt_by_private_key(self, message):
        """使用私钥解密.
            :param message: 需要加密的内容.
            解密之后的内容直接是字符串，不需要在进行转义
        """
        decrypt_result = b""

        max_length = self.get_max_length(self.private_key, False)
        decrypt_message = base64.b64decode(message)
        while decrypt_message:
            input = decrypt_message[:max_length]
            decrypt_message = decrypt_message[max_length:]
            out = rsa.decrypt(input, self.private_key)
            decrypt_result += out
        return decrypt_result

    # 私钥签名
    # 签名 商户私钥 base64转码
    def sign_by_private_key(self, data):
        """私钥签名.
            :param data: 需要签名的内容.
            使用SHA-1 方法进行签名（也可以使用MD5）
            签名之后，需要转义后输出
        """
        signature = rsa.sign(str(data), priv_key=self.private_key, hash_method='SHA-1')
        return base64.b64encode(signature)

    # 公钥验证
    def verify_by_public_key(self, message, signature):
        """公钥验签.
            :param message: 验签的内容.
            :param signature: 对验签内容签名的值（签名之后，会进行b64encode转码，所以验签前也需转码）.
        """
        signature = base64.b64decode(signature)
        return rsa.verify(message, signature, self.public_key)

def test():
    message = 'hell world'
    print("plain text: >>>")
    print(message)
    rsaUtil = RsaUtil()
    encrypy_result = rsaUtil.encrypt_by_public_key(message)
    print("encrypt result: >>>")
    print(encrypy_result)
    decrypt_result = rsaUtil.decrypt_by_private_key(encrypy_result)
    print("decrypt result: >>>")
    print(decrypt_result)
    sign = rsaUtil.sign_by_private_key(message)
    print("sign result: >>>")
    print(sign)
    print("verify result: >>>")
    print(rsaUtil.verify_by_public_key(message, sign))

SignToIPv6 = {}
IPv6ToSign = {}
rsaUtil = RsaUtil()

def interface_identifier_generation():
    randomPool = '0123456789abcdef'
    interfaceIdentifier = ''
    for i in range(16):
        interfaceIdentifier += random.choice(randomPool)
    return interfaceIdentifier


def map_sign_to_ipv6(prefix,sign):
    if SignToIPv6.has_key(sign) == False:
        ipv6 = prefix + interface_identifier_generation()
        SignToIPv6[sign] = ipv6
        IPv6ToSign[ipv6] = sign
        return ipv6
    else:
        return SignToIPv6[sign]
    
# 64 bits prefix, 40 bits nid, 24 bits timestamp
# 16 nibbles prefix, 10 nibbles nid, 6 nibbles timestamp
def ipv6_generation(prefix,nid,timestamp):
    message = nid + timestamp
    sign = rsaUtil.sign_by_private_key(message)
    #print "sign:", sign
    ipv6 = map_sign_to_ipv6(prefix,sign)
    #print "ipv6:", ipv6
    return ipv6

if __name__ == "__main__":
    # test()
    prefix = "2402000000000000"
    nid = "2020214611"
    timestamps = ["071351","071352","071353","071354","071355"] 
    print "*******time change*******"
    for timestamp in timestamps:
        ipv6 = ipv6_generation(prefix,nid,timestamp)
        print nid,timestamp,ipv6

    print "********nid change*******"
    nids = ["2020214611","2020214612","2020214613","2020214614","2020214615"]
    timestamp = "071351"
    for nid in nids:
        ipv6 = ipv6_generation(prefix,nid,timestamp)
        print nid,timestamp,ipv6

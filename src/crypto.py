# -*- coding: UTF-8 -*-
# ------------------- 传输数据加密 -------------------
import os

from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter


# 有限域乘法 GF(2^128): 1 + a + a^2 + a^7 + a^128
def gf_2_128_mul(x, y):
    assert x < (1 << 128)
    assert y < (1 << 128)
    res = 0
    for i in range(127, -1, -1):
        res ^= x * ((y >> i) & 1)
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    assert res < 1 << 128
    return res

class InvalidInputException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)

class InvalidTagException(Exception):
    def __str__(self):
        return 'The authentication tag is invalid.'


# AES-128
# IV（CTR 初始值）: 96 位
class AES_GCM:
    def __init__(self, master_key):
        # AES 秘钥
        self.change_key(master_key)
    
    #  ---------------- 更换 AES 秘钥 ---------------- 
    def change_key(self, master_key):
        if (len(master_key)*8 not in (128, 192, 256)):
            raise InvalidInputException('Error: Master key must be 128, 192 or 256 bit')

        self.__master_key = master_key
        self.__aes_ecb = AES.new(self.__master_key, AES.MODE_ECB)
        self.__auth_key = bytes_to_long(self.__aes_ecb.encrypt(b'\x00' * 16))

        # 先算出有限域乘法表
        table = []
        for i in range(16):
            row = []
            for j in range(256):
                row.append(gf_2_128_mul(self.__auth_key, j << (8 * i)))
            table.append(tuple(row))
        self.__pre_table = tuple(table)

        self.prev_init_value = None  # reset

    #  ---------------- 有限域乘法 ---------------- 
    def __times_auth_key(self, val):
        res = 0
        for i in range(16):
            res ^= self.__pre_table[i][val & 0xFF]
            val >>= 8
        return res

    # ---------------- 计算消息验证码（MAC）值 ----------------
    def __ghash(self, aad, txt):
        len_aad = len(aad)
        len_txt = len(txt)

        # Padding: 把不满 16 个字节的分组数据填满 16 个字节
        # PKCS7: 分组数据缺少几个字节，就在数据的末尾填充几个字节的 0
        if len_aad % 16 == 0:
            data = aad
        else:
            data = aad + b'\x00' * (16 - len_aad % 16)
        if len_txt % 16 == 0:
            data += txt
        else:
            data += txt + b'\x00' * (16 - len_txt % 16)
        
        # 计算 MAC
        tag = 0
        assert len(data) % 16 == 0
        for i in range(len(data) // 16):
            tag ^= bytes_to_long(data[i * 16: (i + 1) * 16])
            tag = self.__times_auth_key(tag)
        tag ^= ((8 * len_aad) << 64) | (8 * len_txt)
        tag = self.__times_auth_key(tag)

        return tag
    
    # ---------------- 加密 ----------------
    def encrypt(self, init_value, plaintext, auth_data=b''):
        # IV 必须为 96 位
        if init_value >= (1 << 96):
            raise InvalidInputException('IV should be 96-bit')
        if init_value == self.prev_init_value:
            raise InvalidInputException('IV must not be reused!')
        self.prev_init_value = init_value

        # --------- 明文 -> 密文 ---------
        len_plaintext = len(plaintext)

        if len_plaintext > 0:
            counter = Counter.new(
                nbits = 32,
                prefix = long_to_bytes(init_value, 12),
                initial_value = 2,
                allow_wraparound = False)
            aes_ctr = AES.new(self.__master_key, AES.MODE_CTR, counter = counter)

            # Padding: 把不满 16 个字节的分组数据填满 16 个字节
            if 0 != len_plaintext % 16:
                padded_plaintext = plaintext + b'\x00' * (16 - len_plaintext % 16)
            else:
                padded_plaintext = plaintext

            ciphertext = aes_ctr.encrypt(padded_plaintext)[:len_plaintext]

        # 明文为空
        else:
            ciphertext = b''

        # --------- MAC（auth_tag） ---------
        auth_tag = self.__ghash(auth_data, ciphertext)
        auth_tag ^= bytes_to_long(self.__aes_ecb.encrypt(long_to_bytes((init_value << 32) | 1, 16)))

        assert auth_tag < (1 << 128)
        return ciphertext, auth_tag

    # ---------------- 解密 ----------------
    def decrypt(self, init_value, ciphertext, auth_tag, auth_data=b''):
        # IV 必须为 96 位
        if init_value >= (1 << 96):
            raise InvalidInputException('IV should be 96-bit')
        # 秘钥必须为 128 位
        if auth_tag >= (1 << 128):
            raise InvalidInputException('Tag should be 128-bit')

        # --------- 完整性校验 --------- 
        # MAC（auth_tag）不匹配：信息被损坏或篡改
        # auth_data: 完整性校验秘钥
        if auth_tag != self.__ghash(auth_data, ciphertext) ^ bytes_to_long(self.__aes_ecb.encrypt(long_to_bytes((init_value << 32) | 1, 16))):
            # print auth_tag
            # print self.__ghash(auth_data, ciphertext) ^ bytes_to_long(self.__aes_ecb.encrypt(long_to_bytes((init_value << 32) | 1, 16)))
            raise InvalidTagException

        # --------- 密文 -> 明文 ---------
        len_ciphertext = len(ciphertext)
        if len_ciphertext > 0:
            counter = Counter.new(
                nbits = 32,
                prefix = long_to_bytes(init_value, 12),
                initial_value = 2,
                allow_wraparound = True)
            aes_ctr = AES.new(self.__master_key, AES.MODE_CTR, counter=counter)

            # Padding: 把不满 16 个字节的分组数据填满 16 个字节
            if len_ciphertext % 16 != 0:
                padded_ciphertext = ciphertext + b'\x00' * (16 - len_ciphertext % 16)
            else:
                padded_ciphertext = ciphertext

            plaintext = aes_ctr.decrypt(padded_ciphertext)[:len_ciphertext]

        # 密文为空
        else:
            plaintext = b''

        return plaintext


# DH 秘钥协商算法（AES 秘钥）
def diffiehellman(sock, bits=2048):
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2
    a = bytes_to_long(os.urandom(32)) # 256bit number
    xA = pow(g, a, p)

    sock.send(long_to_bytes(xA))
    b = bytes_to_long(sock.recv(256))

    s = pow(b, a, p)
    return SHA256.new(long_to_bytes(s)).digest()
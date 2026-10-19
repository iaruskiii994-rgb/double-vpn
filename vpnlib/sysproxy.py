"""Включение/выключение системного прокси Windows (с запоминанием прежних настроек)."""
import json
import os
import subprocess
from pathlib import Path

BACKUP = Path(__file__).resolve().parent.parent / "core" / "proxy_backup.json"
KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
FIELDS = {"ProxyEnable": 4, "ProxyServer": 1, "ProxyOverride": 1}  # имя -> REG_DWORD / REG_SZ
BYPASS = ";".join(["localhost", "127.*", "10.*", *(f"172.{i}.*" for i in range(16, 32)),
                   "192.168.*", "<local>"])

SUPPORTED = os.name == "nt"
if SUPPORTED:
    import ctypes
    import winreg


def _read():
    state = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY) as k:
        for name in FIELDS:
            try:
                state[name] = winreg.QueryValueEx(k, name)[0]
            except FileNotFoundError:
                state[name] = None
    return state


def _write(state):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE) as k:
        for name, kind in FIELDS.items():
            if state.get(name) is None:
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(k, name, 0, kind, state[name])
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH


def enable(http_port):
    if not SUPPORTED:
        return
    if not BACKUP.exists():
        BACKUP.parent.mkdir(exist_ok=True)
        BACKUP.write_text(json.dumps(_read()), encoding="utf-8")
    _write({"ProxyEnable": 1, "ProxyServer": f"127.0.0.1:{http_port}", "ProxyOverride": BYPASS})


VPN_WORDS = ("tunnel", "tun", "tap-", "wintun", "wireguard", "vpn", "happ", "hiddify", "sing-box",
             "clash", "outline", "amnezia", "nekoray", "v2ray", "xray")


def other_vpn():
    """Имя чужого VPN-адаптера, через который сейчас идёт интернет (TUN у Happ, v2rayN, Hiddify...), или ''."""
    if not SUPPORTED:
        return ""
    ps = ("$r = Find-NetRoute -RemoteIPAddress 1.1.1.1 -ErrorAction SilentlyContinue | Select-Object -First 1; "
          "if ($r) { (Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue).InterfaceDescription }")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, timeout=15,
                             creationflags=0x08000000).stdout.decode(errors="replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return out if any(w in out.lower() for w in VPN_WORDS) else ""


def restore():
    """Возвращает настройки, которые были до включения (в т.ч. после вылета программы)."""
    if not SUPPORTED or not BACKUP.exists():
        return
    _write(json.loads(BACKUP.read_text(encoding="utf-8")))
    BACKUP.unlink()

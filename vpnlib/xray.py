"""Скачивание ядра Xray, сборка конфигов и запуск процесса."""
import atexit
import hashlib
import io
import json
import os
import platform
import socket
import subprocess
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE_DIR = ROOT / "core"
XRAY_EXE = CORE_DIR / ("xray.exe" if os.name == "nt" else "xray")
RELEASE_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) double_vpn/1.0"
NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# не 10808/10809 — их обычно занимают v2rayN/Happ
SOCKS_PORT = 10828
HTTP_PORT = 10829
AUTO_PROBE_URL = "http://cp.cloudflare.com/generate_204"  # чем режим АВТО пингует серверы


def auto_balancer(prefix="auto-"):
    """Балансировщик «⚡ АВТО»: каждые 30 с пингует все серверы, помнит последние 6 замеров,
    выкидывает те, что часто не отвечают или отвечают дольше 1.5 с, и держит трафик на 2 самых
    стабильных (с наименьшим разбросом задержки), раскидывая соединения между ними — если один
    просел, страдает только часть соединений, а не всё. Запасной — наш самый быстрый сервер (не direct).
    Возвращает (balancer, burstObservatory) — так же устроен шаблон Remnawave, с которым работает Happ."""
    balancer = {"tag": "auto", "selector": [prefix], "fallbackTag": prefix + "0",
                "strategy": {"type": "leastLoad",
                             "settings": {"expected": 2, "maxRTT": "1500ms", "tolerance": 0.3}}}
    observatory = {"subjectSelector": [prefix], "pingConfig": {
        "destination": AUTO_PROBE_URL, "connectivity": "", "interval": "30s", "sampling": 6, "timeout": "5s"}}
    return balancer, observatory


def http_get(url, timeout=30, opener=None, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with (opener.open if opener else urllib.request.urlopen)(req, timeout=timeout) as r:
        return r.read()


def _asset_name():
    arm = platform.machine().lower() in ("arm64", "aarch64")
    if os.name == "nt":
        return "Xray-windows-arm64-v8a.zip" if arm else "Xray-windows-64.zip"
    if platform.system() == "Darwin":
        return "Xray-macos-arm64-v8a.zip" if arm else "Xray-macos-64.zip"
    return "Xray-linux-arm64-v8a.zip" if arm else "Xray-linux-64.zip"


def ensure_xray(log=print):
    """Качает Xray с официального GitHub (XTLS/Xray-core), если его ещё нет."""
    if XRAY_EXE.exists():
        return XRAY_EXE
    name = _asset_name()
    log(f"Скачиваю ядро Xray ({name}) с github.com/XTLS/Xray-core ...")
    # в облаке GitHub у общих серверов маленький лимит анонимных запросов к API — подписываемся токеном
    auth = {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"} if os.environ.get("GITHUB_TOKEN") else {}
    release = json.loads(http_get(RELEASE_API, headers=auth))
    assets = {a["name"]: a["browser_download_url"] for a in release["assets"]}
    data = http_get(assets[name], timeout=120)
    digest = http_get(assets[name + ".dgst"]).decode()
    expected = next(
        line.split("=", 1)[1].strip().lower()
        for line in digest.splitlines()
        if line.upper().startswith("SHA2-256")
    )
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError("Контрольная сумма Xray не совпала — файл повреждён")
    CORE_DIR.mkdir(exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for member in z.namelist():
            if member in (XRAY_EXE.name, "geoip.dat", "geosite.dat"):
                (CORE_DIR / member).write_bytes(z.read(member))
    if os.name != "nt":
        XRAY_EXE.chmod(0o755)
    log(f"Xray {release['tag_name']} установлен в {CORE_DIR}")
    return XRAY_EXE


def free_ports(n):
    socks, ports = [], []
    try:
        for _ in range(n):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            socks.append(s)
            ports.append(s.getsockname()[1])
    finally:
        for s in socks:
            s.close()
    return ports


def port_open(port, timeout=0.3):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def config_ok(config, path):
    """`xray run -test`: проверяет конфиг, ничего не запуская."""
    path.write_text(json.dumps(config), encoding="utf-8")
    r = subprocess.run(
        [str(XRAY_EXE), "run", "-test", "-c", str(path)],
        cwd=CORE_DIR, capture_output=True, creationflags=NO_WINDOW, timeout=60,
    )
    return r.returncode == 0, r.stdout.decode(errors="replace")


class XrayProcess:
    running = set()

    def __init__(self, config, name="xray"):
        CORE_DIR.mkdir(exist_ok=True)
        self.cfg_path = CORE_DIR / f"{name}.json"
        self.log_path = CORE_DIR / f"{name}.log"
        self.cfg_path.write_text(json.dumps(config, indent=1), encoding="utf-8")
        self._log = open(self.log_path, "w", encoding="utf-8")
        self.proc = subprocess.Popen(
            [str(XRAY_EXE), "run", "-c", str(self.cfg_path)],
            cwd=CORE_DIR, stdout=self._log, stderr=subprocess.STDOUT,
            creationflags=NO_WINDOW,
        )
        XrayProcess.running.add(self)

    def wait_ports(self, ports, timeout=10):
        deadline = time.time() + timeout
        pending = list(ports)
        while pending and time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            pending = [p for p in pending if not port_open(p)]
            if pending:
                time.sleep(0.1)
        return not pending

    def alive(self):
        return self.proc.poll() is None

    def tail_log(self, n=15):
        try:
            return "\n".join(self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:])
        except OSError:
            return ""

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self._log.close()
        XrayProcess.running.discard(self)


@atexit.register
def stop_all():
    for p in list(XrayProcess.running):
        p.stop()


def client_config(outbound, first_hop=None, ru_direct=True):
    """Конфиг для подключения: локальные SOCKS5 и HTTP.
    outbound — один сервер или список (режим АВТО: Xray пингует их и сам берёт самый быстрый живой)."""
    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    auto = isinstance(outbound, list)
    outbounds = [json.loads(json.dumps(o)) for o in (outbound if auto else [outbound])]
    for i, ob in enumerate(outbounds):
        ob["tag"] = f"auto-{i}" if auto else "proxy"
        if first_hop:  # DOUBLE VPN: выходной сервер соединяется через первый хоп
            ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = "hop1"
    if first_hop:
        outbounds.append(dict(json.loads(json.dumps(first_hop)), tag="hop1"))
    outbounds += [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]

    rules = [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]
    if ru_direct:
        rules += [
            {"type": "field", "outboundTag": "direct",
             "domain": ["regexp:\\.ru$", "regexp:\\.su$", "regexp:\\.xn--p1ai$", "geosite:category-ru"]},
            {"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"},
        ]
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
             "settings": {"udp": True}, "sniffing": sniff},
            {"tag": "http-in", "listen": "127.0.0.1", "port": HTTP_PORT, "protocol": "http",
             "sniffing": sniff},
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }
    if auto:
        rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "auto"})
        balancer, config["burstObservatory"] = auto_balancer()
        config["routing"]["balancers"] = [balancer]
    return config


def tester_config(outbounds, ports):
    """Один процесс Xray на пачку серверов: порт i -> сервер i."""
    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {"tag": f"in{i}", "listen": "127.0.0.1", "port": p, "protocol": "http"}
            for i, p in enumerate(ports)
        ],
        "outbounds": [dict(ob, tag=f"out{i}") for i, ob in enumerate(outbounds)],
        "routing": {"rules": [
            {"type": "field", "inboundTag": [f"in{i}"], "outboundTag": f"out{i}"}
            for i in range(len(ports))
        ]},
    }

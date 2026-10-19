"""Раздача подписки другим устройствам: http://<IP компьютера>:10830/sub (для Happ — /happ)"""
import base64
import ipaddress
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import collector, links, names, xray

PORT = 10830
TITLE = "DOUBLE VPN"
AUTO_NAME = "⚡ АВТО (самый быстрый)"  # Happ показывает до 30 символов
AUTO_POOL = 30
SUB_MAIN = 250  # сколько лучших обычных серверов отдаём в подписку
SUB_WHITE = 30  # и сколько лучших «обход белых списков»
SUB_MAX_PING = 2500  # мс: медленнее — не берём, такие первыми превращаются в «н/д»

# (сеть, подпись) — в таком порядке и показываем адреса
NETWORKS = [
    ("192.168.0.0/16", "Wi-Fi / домашняя сеть"),
    ("10.0.0.0/8", "локальная сеть"),
    ("100.64.0.0/10", "Tailscale — работает из любой сети, если Tailscale стоит и на телефоне"),
    ("26.0.0.0/8", "Radmin VPN"),
]


def lan_addresses():
    """[(ip, подпись)] — адреса этого компьютера, по которым до него достучатся другие устройства."""
    try:
        ips = {a[4][0] for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)}
    except OSError:
        ips = set()
    found = []
    for net, label in NETWORKS:
        found += [(ip, label) for ip in sorted(ips) if ipaddress.ip_address(ip) in ipaddress.ip_network(net)]
    return found


def _alive():
    """Серверы для подписки: только лучшие (бесплатные медленные умирают первыми и в Happ висят «н/д»).
    Порядок показа: по скорости, обход белых списков — в конце. Полный список остаётся в программе на ПК."""
    servers = collector.load()
    alive = [s for s in servers if s.get("ping")] or servers
    main = [s for s in alive if not s.get("white") and (s.get("ping") or 0) <= SUB_MAX_PING]
    white = sorted((s for s in alive if s.get("white")), key=lambda s: -(s.get("speed") or 0))
    # сначала серверы поближе к России (ниже пинг у друзей), остальные — если мест хватает
    main = sorted(main, key=lambda s: (not collector.near(s), collector.rank(s)))[:SUB_MAIN]
    return sorted(main + white[:SUB_WHITE], key=collector.rank)


def display_name(s):
    """Название с флагом страны выхода: «🇩🇪 ТУРБОВПН ГЕРМАНИЯ БЕРЛИН КЛАСИК»."""
    return f"{names.flag(s.get('country_code'))} {s['name']}"


def _links(servers):
    return [links.rename(s["link"], display_name(s)) for s in servers]


def subscription_body():
    """base64 для раздачи по локальной сети (название и автообновление — в HTTP-заголовках)."""
    servers = _alive()
    return base64.b64encode("\n".join(_links(servers)).encode("utf-8")), len(servers)


def subscription_text():
    """Обычный текст со служебными строками в начале — их читают Happ, Hiddify, v2rayN
    (так делают, когда нельзя задать HTTP-заголовки, например в GitHub Gist)."""
    servers = _alive()
    head = [f"#profile-title: base64:{base64.b64encode(TITLE.encode()).decode()}",
            "#profile-update-interval: 1"]
    return "\n".join(head + _links(servers)) + "\n", len(servers)


def _happ_config(remarks, outbounds, auto=False):
    """Полный конфиг Xray для одного пункта в Happ — по образцу шаблона Remnawave, с которым Happ работает.
    auto=True — балансировщик: раз в минуту пингует все серверы и ведёт трафик через самый быстрый."""
    sniff = {"enabled": True, "routeOnly": False, "destOverride": ["http", "tls", "quic"]}
    obs = [dict(json.loads(json.dumps(o)), tag=f"auto-{i}" if auto else "proxy") for i, o in enumerate(outbounds)]
    rules = [{"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]
    config = {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "inbounds": [
            {"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks",
             "settings": {"udp": True, "auth": "noauth"}, "sniffing": sniff},
            {"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http",
             "settings": {"allowTransparent": False}, "sniffing": sniff},
        ],
        "outbounds": obs + [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    if auto:
        rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "auto"})
        balancer, config["burstObservatory"] = xray.auto_balancer()
        config["routing"]["balancers"] = [balancer]
    return config


def happ_json():
    """Подписка для Happ в формате Xray JSON: первым «⚡ АВТО» (сам выбирает самый быстрый из 30),
    дальше все серверы с флагами, обход белых списков — в конце."""
    servers = _alive()
    pool = collector.auto_pool(servers, AUTO_POOL, basic_only=True)
    configs = [_happ_config(AUTO_NAME, [s["outbound"] for s in pool], auto=True)] if pool else []
    configs += [_happ_config(display_name(s), [s["outbound"]]) for s in servers]
    return json.dumps(configs, ensure_ascii=False, separators=(",", ":")), len(servers)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 — имя задаёт http.server
        path = self.path.split("?")[0].rstrip("/")
        if path == "/sub":
            body, _ = subscription_body()
            kind = "text/plain"
        elif path == "/happ":  # для Happ: с «⚡ АВТО» первым
            text, _ = happ_json()
            body, kind = text.encode("utf-8"), "application/json"
        else:
            self.send_error(404, "Subscription is at /sub (or /happ for Happ)")
            return
        self.send_response(200)
        self.send_header("Content-Type", f"{kind}; charset=utf-8")
        # заголовки, которые понимают Happ / Hiddify / v2rayN: имя подписки и автообновление раз в час
        self.send_header("profile-title", "base64:" + base64.b64encode(TITLE.encode()).decode())
        self.send_header("profile-update-interval", "1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class SubscriptionServer:
    def __init__(self, port=PORT, host="0.0.0.0"):
        self.port = port
        self.host = host
        self.httpd = None

    def start(self):
        if not self.httpd:
            self.httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
            threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def urls(self):
        return [(f"http://{ip}:{self.port}/sub", label) for ip, label in lan_addresses()]

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None

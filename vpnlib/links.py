"""Разбор ссылок vless:// vmess:// trojan:// ss:// hysteria2:// в outbound для Xray."""
import base64
import ipaddress
import json
from urllib.parse import parse_qs, quote, unquote, urlsplit

SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
}
NETWORKS = {"tcp", "raw", "ws", "grpc", "xhttp", "splithttp", "httpupgrade"}
SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2"}


class Unsupported(ValueError):
    pass


def b64decode(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _query(query):
    return {k: v[-1] for k, v in parse_qs(query, keep_blank_values=True).items()}


def _stream(q, host, default_security="none"):
    net = (q.get("type") or q.get("net") or "tcp").lower()
    if net not in NETWORKS:
        raise Unsupported(f"транспорт {net}")
    net = {"raw": "tcp", "splithttp": "xhttp"}.get(net, net)
    path = q.get("path") or ""
    hhost = q.get("host") or ""
    ss = {"network": net}
    if net == "tcp" and q.get("headerType") == "http":
        ss["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [path or "/"], "headers": {"Host": [h for h in hhost.split(",") if h]}}}}
    elif net == "ws":
        ss["wsSettings"] = {"path": path or "/", "host": hhost}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": path or "/", "host": hhost}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": q.get("serviceName") or path,
                              "multiMode": q.get("mode") == "multi"}
        if q.get("authority"):
            ss["grpcSettings"]["authority"] = q["authority"]
    elif net == "xhttp":
        x = {"path": path or "/", "host": hhost, "mode": q.get("mode") or "auto"}
        if q.get("extra"):
            try:
                x["extra"] = json.loads(q["extra"])
            except ValueError:
                pass
        ss["xhttpSettings"] = x

    security = (q.get("security") or default_security).lower()
    sni = q.get("sni") or q.get("peer") or hhost.split(",")[0] or ("" if is_ip(host) else host)
    fp = q.get("fp") or "chrome"
    if security == "tls":
        tls = {"serverName": sni, "fingerprint": fp}
        if q.get("alpn"):
            tls["alpn"] = [a for a in q["alpn"].split(",") if a]
        ss["security"] = "tls"
        ss["tlsSettings"] = tls
    elif security == "reality":
        if not q.get("pbk"):
            raise Unsupported("reality без pbk")
        r = {"serverName": sni, "fingerprint": fp, "publicKey": q["pbk"],
             "shortId": q.get("sid", ""), "spiderX": q.get("spx") or "/"}
        if q.get("pqv"):
            r["mldsa65Verify"] = q["pqv"]
        ss["security"] = "reality"
        ss["realitySettings"] = r
    elif security not in ("none", ""):
        raise Unsupported(f"security {security}")
    return ss


def _vless(u, q):
    enc = q.get("encryption") or "none"
    if enc != "none" and not enc.startswith("mlkem768x25519plus"):
        raise Unsupported("vless encryption")  # в агрегаторах бывает мусор вроде none=@channel
    user = {"id": unquote(u.username or ""), "encryption": enc}
    if q.get("flow"):
        user["flow"] = q["flow"]
    return {
        "protocol": "vless",
        "settings": {"vnext": [{"address": u.hostname, "port": u.port, "users": [user]}]},
        "streamSettings": _stream(q, u.hostname),
    }


def _trojan(u, q):
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": u.hostname, "port": u.port,
                                  "password": unquote(u.username or "")}]},
        "streamSettings": _stream(q, u.hostname, default_security="tls"),
    }


def _hysteria2(u, q):
    if q.get("obfs") or q.get("insecure") == "1":
        raise Unsupported("hysteria2 obfs/insecure")
    auth = unquote(u.username or "")
    if u.password:
        auth += ":" + unquote(u.password)
    sni = q.get("sni") or ("" if is_ip(u.hostname) else u.hostname)
    tls = {"serverName": sni}
    if q.get("alpn"):
        tls["alpn"] = q["alpn"].split(",")
    return {
        "protocol": "hysteria",
        "settings": {"version": 2, "address": u.hostname, "port": u.port},
        "streamSettings": {"network": "hysteria", "security": "tls", "tlsSettings": tls,
                           "hysteriaSettings": {"version": 2, "auth": auth}},
    }


def _vmess(body):
    d = json.loads(b64decode(body).decode("utf-8", errors="replace"))
    host, port = str(d.get("add", "")).strip(), int(d.get("port", 0))
    q = {
        "type": d.get("net") or "tcp", "headerType": d.get("type"), "host": d.get("host") or "",
        "path": d.get("path") or "", "security": "tls" if d.get("tls") == "tls" else "none",
        "sni": d.get("sni") or "", "alpn": d.get("alpn") or "", "fp": d.get("fp") or "",
    }
    if q["type"] == "grpc":
        q["serviceName"] = q["path"]
    ob = {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": host, "port": port, "users": [
            {"id": d.get("id", ""), "security": d.get("scy") or "auto"}]}]},
        "streamSettings": _stream(q, host),
    }
    return ob, host, port, str(d.get("ps", ""))


def _ss(rest):
    body, _, frag = rest.partition("#")
    body, _, query = body.partition("?")
    if "plugin" in _query(query):
        raise Unsupported("ss plugin")
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            decoded = b64decode(unquote(userinfo)).decode()
            if ":" not in decoded:
                raise ValueError
            userinfo = decoded
        except ValueError:
            userinfo = unquote(userinfo)
    else:
        userinfo, hostport = b64decode(body).decode().rsplit("@", 1)
    method, password = userinfo.split(":", 1)
    u = urlsplit("//" + hostport)
    if method.lower() not in SS_METHODS:
        raise Unsupported(f"ss {method}")
    ob = {"protocol": "shadowsocks", "settings": {"servers": [
        {"address": u.hostname, "port": u.port, "method": method.lower(), "password": password}]}}
    return ob, u.hostname, u.port, unquote(frag)


def parse(link):
    """Возвращает dict(proto, host, port, remark, outbound) или бросает исключение."""
    link = link.strip()
    scheme = link.split("://", 1)[0].lower()
    rest = link[len(scheme) + 3:]
    if scheme == "vmess":
        ob, host, port, remark = _vmess(rest.split("#")[0])
    elif scheme == "ss":
        ob, host, port, remark = _ss(rest)
    elif scheme in ("vless", "trojan", "hysteria2", "hy2"):
        u = urlsplit(link)
        q = _query(u.query)
        host, port, remark = u.hostname, u.port, unquote(u.fragment)
        ob = {"vless": _vless, "trojan": _trojan}.get(scheme, _hysteria2)(u, q)
        scheme = "hysteria2" if scheme == "hy2" else scheme
    else:
        raise Unsupported(scheme)
    if not host or not port or not 0 < int(port) < 65536:
        raise ValueError("нет адреса/порта")
    if not is_ip(host):
        host.encode("idna")  # отсеивает кривые домены (пустые/слишком длинные части) — UnicodeError
    return {"proto": scheme, "host": host, "port": int(port), "remark": remark, "outbound": ob}


def transport(s):
    """Подпись для колонки «Транспорт»: xhttp+reality, ws+tls, tcp+reality, hy2..."""
    if s["proto"] == "hysteria2":
        return "hy2 (udp)"
    ss = s["outbound"].get("streamSettings", {})
    net, sec = ss.get("network", "tcp"), ss.get("security", "none")
    return net if sec in ("none", "") else f"{net}+{sec}"


def rename(link, name):
    """Меняет название сервера внутри ссылки (для экспорта в v2rayN/Hiddify/v2rayNG)."""
    link = link.strip()
    if link.lower().startswith("vmess://"):
        d = json.loads(b64decode(link[8:].split("#")[0]))
        d["ps"] = name
        return "vmess://" + base64.b64encode(json.dumps(d, ensure_ascii=False).encode()).decode()
    return link.split("#", 1)[0] + "#" + quote(name)


def flag_country(text):
    """🇩🇪 в названии -> 'DE'."""
    chars = [c for c in text if 0x1F1E6 <= ord(c) <= 0x1F1FF]
    for a, b in zip(chars[::2], chars[1::2]):
        return chr(ord(a) - 0x1F1E6 + 65) + chr(ord(b) - 0x1F1E6 + 65)
    return ""

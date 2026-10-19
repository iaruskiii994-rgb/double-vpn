"""Сбор бесплатных серверов из публичных списков, реальная проверка через Xray, отбор лучших."""
import contextlib
import json
import os
import random
import socket
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import links, names, xray

ROOT = Path(__file__).resolve().parent.parent
SERVERS_FILE = ROOT / "servers.json"
SUB_FILE = ROOT / "servers_sub.txt"

GH = "https://raw.githubusercontent.com/"
IG = GH + "igareck/vpn-configs-for-russia/main/"
KZ = GH + "Maskkost93/kizyak-vpn-4.0/main/"
GOIDA = GH + "Hidashimora/free-vpn-anti-rkn/main/configs/"  # зеркало goida-vpn-configs (оригинал удалён)
# Публичные подборки под РФ, в порядке проверки: (url, конфиги для обхода белых списков?)
SOURCES = [
    (IG + "Vless-Reality-White-Lists-Rus-Mobile.txt", True),
    (IG + "WHITE-CIDR-RU-checked.txt", True),
    (IG + "WHITE-CIDR-RU-all.txt", True),
    (IG + "WHITE-SNI-RU-all.txt", True),
    (GH + "RKPchannel/RKP_bypass_configs/main/whitelist.txt", True),
    # обход белых списков: вход через российские сети/SNI из белых списков, выход — где получится
    (GH + "zieng2/wl/main/vless_universal.txt", True),
    (GH + "zieng2/wl/main/vless_lite.txt", True),
    (GH + "zieng2/wl/main/vless.txt", True),
    (GH + "ByeWhiteLists/ByeWhiteLists2/main/ByeWhiteLists2.txt", True),
    ("https://s3c3.001.gpucloud.ru/wlr/wl.txt", True),
    ("https://etoneya.su/whitelist", True),
    (GOIDA + "26.txt", True),
    (GH + "slxkware/Vless-list/main/White%20Vless.txt", True),
    (GH + "kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/vless.txt", True),
    (GH + "kort0881/vpn-vless-configs-russia/main/data/githubmirror/ru-sni/trojan.txt", True),
    (KZ + "kizyakbeta8.txt", False),
    (KZ + "kizyakbeta7.txt", False),
    (KZ + "kizyakbeta6.txt", False),
    (KZ + "kizyakbeta6BL.txt", False),
    (GOIDA + "23.txt", False),
    (GOIDA + "5.txt", False),
    (GOIDA + "15.txt", False),
    (GOIDA + "16.txt", False),
    (GH + "partnermbp/RUS_VLESS/main/subscription.txt", False),
    (GH + "snakem982/proxypool/main/source/v2ray-2.txt", False),
    (IG + "BLACK_VLESS_RUS.txt", False),
    (IG + "BLACK_VLESS_RUS_mobile.txt", False),
    (IG + "BLACK_SS%2BAll_RUS.txt", False),
    (GOIDA + "22.txt", False),
    (GOIDA + "6.txt", False),
    (GH + "v0id9/vpn-configs/main/vpn.txt", False),
    (GH + "aviamastersgh/vpn-free-russia/main/ru_configs.txt", False),
    (GH + "RKPchannel/RKP_bypass_configs/main/blacklist.txt", False),
    # подборки именно xhttp
    (GH + "lanopivijo93782-ops/hiddify-vless-xhttp-parser/main/docs/sub/vless.txt", False),
    (GH + "Surfboardv2ray/xhttp-parser/main/output/xhttp.txt", False),
]
# Большие агрегаторы (из РФ живых 0.1–2%) — по порядку, пока не наберём нужное число
EXTRA_SOURCES = [
    *(GH + f"Au1rxx/free-vpn-subscriptions/main/output/all-verified/v2ray-base64-{i:04}.txt" for i in range(1, 11)),
    GH + "barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    GH + "MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    GH + "mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    GH + "SoliSpirit/v2ray-configs/main/all_configs.txt",
    GH + "ebrasha/free-v2ray-public-list/main/all_extracted_configs.txt",
    GH + "kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/vless.txt",
    GH + "kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/trojan.txt",
    GH + "kort0881/vpn-vless-configs-russia/main/data/githubmirror/clean/ss.txt",
    *(GOIDA + f"{i}.txt" for i in (1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14, 17, 18, 19, 20, 24, 25, 21, 2)),
]
TEST_URL = "http://cp.cloudflare.com/generate_204"
# 256 КБ — ловит серверы, которые отвечают на пинг, но «замерзают» на реальном трафике
DOWNLOAD_BYTES = 256 * 1024
DOWNLOAD_URLS = [f"http://speed.cloudflare.com/__down?bytes={DOWNLOAD_BYTES}",
                 "http://speedtest.tele2.net/10MB.zip"]
GEO_URLS = ["http://ip-api.com/json/?fields=status,country,countryCode,city,query",
            "http://ipinfo.io/json"]
TARGET = 1000  # потолок списка: столько рабочих из РФ обычно не набирается, берём сколько есть
MAX_PER_EXIT_IP = 2
# страны с выходом «поближе» к России — у них ниже пинг для пользователей из РФ. Они идут в АВТО и в
# подписку первыми: облако GitHub проверяет из США, и без этого в лучших оказались бы американские серверы
NEAR_RU = set("AT BE BG CH CY CZ DE DK EE ES FI FR GB GR HR HU IE IS IT LT LU LV MD MT NL NO PL PT RO RS SE "
              "SI SK AL BA ME MK UA BY TR GE AM AZ KZ UZ KG AE IL".split())
IN_CLOUD = bool(os.environ.get("GITHUB_ACTIONS"))


def near(s):
    return (s.get("country_code") or "") in NEAR_RU
SPEED_WORKERS = 32  # параллельных загрузок при проверке «качает / не качает»
PRECISE_TOP = 120  # скольким лучшим серверам мерить скорость точно (1 МБ)
ENDURANCE_TOP = 40  # скольких кандидатов в «⚡ АВТО» гонять длинной загрузкой (3 МБ)
ENDURANCE_BYTES = 3 * 1024 * 1024


def _fetch_links(url):
    text = xray.http_get(url, timeout=90).decode("utf-8", errors="replace")
    if "://" not in text[:5000]:  # подписка в base64
        try:
            text = links.b64decode("".join(text.split())).decode("utf-8", errors="replace")
        except ValueError:
            return []
    return [l.strip() for l in text.splitlines() if "://" in l and not l.startswith("#")]


def link_key(link):
    """Ключ для отсева дублей без полного разбора: ссылка без названия."""
    if link[:8].lower() == "vmess://":
        try:
            d = json.loads(links.b64decode(link[8:].split("#")[0]))
            d.pop("ps", None)
            return "vmess|" + json.dumps(d, sort_keys=True)
        except (ValueError, TypeError):
            return None
    return link.split("#", 1)[0]


def gather(log=print):
    """Скачивает все источники. Возвращает (подборки для РФ, агрегаторы) — лёгкие dict(link, key, white)."""
    sources = [(url, white, True) for url, white in SOURCES] + [(url, False, False) for url in EXTRA_SOURCES]
    with ThreadPoolExecutor(12) as ex:
        futures = [(src, ex.submit(_fetch_links, src[0])) for src in sources]
        seen, prio, rest = set(), [], []
        for (url, white, priority), fut in futures:
            try:
                raw = fut.result()
            except Exception as e:  # noqa: BLE001 — упавший источник просто пропускаем
                log(f"  ✗ {url.rsplit('/', 1)[-1]}: {e}")
                continue
            found = []
            for link in raw:
                key = link_key(link)
                if key and key not in seen and link.split("://")[0].lower() in links.SCHEMES:
                    seen.add(key)
                    found.append({"link": link, "key": key, "white": white})
            if not priority:  # в огромных агрегаторах перемешиваем, порядок источников сохраняем
                random.shuffle(found)
            (prio if priority else rest).extend(found)
            log(f"  ✓ {url.removeprefix(GH).split('/')[0]}/{url.rsplit('/', 1)[-1]}: "
                f"{len(raw)} ссылок, новых {len(found)}")
    return prio, rest


def parse_all(items):
    out = []
    for c in items:
        try:
            s = links.parse(c["link"])
        except Exception:  # noqa: BLE001 — неподдерживаемые/битые ссылки
            continue
        out.append({**c, **s})
    return out


def _tcp_ok(s, timeout=4):
    if s["proto"] == "hysteria2":  # UDP, по TCP не проверить
        return True
    try:
        with socket.create_connection((s["host"], s["port"]), timeout=timeout):
            return True
    except (OSError, UnicodeError, ValueError):  # в том числе кривые доменные имена
        return False


def tcp_filter(servers, workers=500):
    with ThreadPoolExecutor(workers) as ex:
        return [s for s, ok in zip(servers, ex.map(_tcp_ok, servers)) if ok]


def _valid_subset(servers, path):
    """Выкидывает серверы, конфиг которых Xray не принимает (делением пополам)."""
    if not servers:
        return []
    ok, _ = xray.config_ok(xray.tester_config([s["outbound"] for s in servers],
                                              range(20000, 20000 + len(servers))), path)
    if ok:
        return servers
    if len(servers) == 1:
        return []
    mid = len(servers) // 2
    return _valid_subset(servers[:mid], path) + _valid_subset(servers[mid:], path)


def proxy_opener(port):
    proxy = f"http://127.0.0.1:{port}"
    return urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))


def ping(opener, timeout):
    """Время ответа через прокси в мс или None."""
    try:
        t0 = time.perf_counter()
        req = urllib.request.Request(TEST_URL, headers={"User-Agent": xray.UA})
        with opener.open(req, timeout=timeout) as r:
            if r.status not in (200, 204):
                return None
        return int((time.perf_counter() - t0) * 1000)
    except Exception:  # noqa: BLE001 — любой сбой = сервер не работает
        return None


def _read(resp, limit, deadline):
    """Читает до limit байт, но не дольше deadline: read1 отдаёт данные сразу, поэтому сервер,
    который цедит по байту, не подвесит проверку."""
    data = bytearray()
    while len(data) < limit and time.perf_counter() < deadline:
        chunk = resp.read1(min(65536, limit - len(data)))
        if not chunk:
            break
        data += chunk
    return bytes(data)


def speed(opener, size=DOWNLOAD_BYTES, timeout=10):
    """Качает size байт через прокси. Мбит/с или None, если сервер не тянет настоящий трафик
    (зависает после первых килобайт — так режут многие бесплатные серверы)."""
    for url in DOWNLOAD_URLS:
        url = url.replace(f"bytes={DOWNLOAD_BYTES}", f"bytes={size}")
        req = urllib.request.Request(url, headers={"User-Agent": xray.UA, "Range": f"bytes=0-{size - 1}"})
        t0 = time.perf_counter()
        try:
            with opener.open(req, timeout=5) as r:
                got = len(_read(r, size, t0 + timeout))
        except urllib.error.HTTPError:
            continue  # сайт для теста не пустил — пробуем запасной
        except Exception:  # noqa: BLE001 — завис или оборвал соединение: сервер не годится
            return None
        return round(got * 8 / (time.perf_counter() - t0) / 1e6, 1) if got >= size else None
    return None


def measure_speed(servers, log=print, size=1024 * 1024, workers=3):
    """Точный замер скорости (1 МБ, по несколько серверов за раз, чтобы не мешали друг другу)."""
    def one(sp):
        sp[0]["speed"] = speed(proxy_opener(sp[1]), size=size, timeout=20) or sp[0].get("speed")
    if servers and _run_on_tester(servers, one, workers, log, "speedtest"):
        log(f"Точная скорость замерена для {len(servers)} лучших серверов")


def endurance(servers, log=print, workers=3):
    """Длинная загрузка (3 МБ) у кандидатов в «⚡ АВТО». Бывает, что сервер быстро отдаёт первые
    сотни килобайт, а потом режет скорость — в АВТО такой дал бы долгие просадки.
    Проставляет s['stable'] и s['speed'] = скорость на длинной загрузке."""
    def one(sp):
        sustained = speed(proxy_opener(sp[1]), size=ENDURANCE_BYTES, timeout=30)
        sp[0]["stable"] = bool(sustained)
        if sustained:
            sp[0]["speed"] = sustained
    if servers and _run_on_tester(servers, one, workers, log, "endurance"):
        ok = sum(1 for s in servers if s.get("stable"))
        log(f"Длинная загрузка 3 МБ: держат скорость {ok} из {len(servers)} кандидатов в АВТО")


def measure_all(servers, log=print):
    """Точная скорость у лучших + проверка на выносливость у кандидатов в АВТО."""
    for s in servers:
        s["stable"] = False
    measure_speed(sorted(servers, key=lambda s: -(s.get("speed") or 0))[:PRECISE_TOP], log=log)
    endurance(auto_pool(servers, ENDURANCE_TOP, prefer_stable=False), log=log)


def exit_info(opener, timeout):
    """Где на самом деле выходит трафик: dict(country, country_code, city, exit_ip) или None."""
    for url in GEO_URLS:
        try:
            with opener.open(urllib.request.Request(url, headers={"User-Agent": xray.UA}), timeout=timeout) as r:
                d = json.loads(_read(r, 65536, time.perf_counter() + timeout))
        except Exception:  # noqa: BLE001 — некоторые серверы режут отдельные сайты
            continue
        if d.get("status") == "success":
            return {"country": d["country"], "country_code": d["countryCode"],
                    "city": d["city"], "exit_ip": d["query"]}
        if d.get("country") and d.get("ip"):  # ipinfo.io
            return {"country": "", "country_code": d["country"], "city": d.get("city", ""), "exit_ip": d["ip"]}
    return None


def _check_traffic(s, port, geo):
    opener = proxy_opener(port)
    s["speed"] = speed(opener)
    if not s["speed"]:
        s["ping"] = None  # пинг есть, а трафик не идёт — для нас это мёртвый сервер
    elif geo:
        s.update(exit_info(opener, 8) or {})


def _run_on_tester(servers, fn, workers, log=print, name="tester"):
    """Поднимает Xray с серверами на отдельных портах и вызывает fn((server, port)) в workers потоков."""
    if not servers:
        return True
    ports = xray.free_ports(len(servers))
    proc = xray.XrayProcess(xray.tester_config([s["outbound"] for s in servers], ports), name)
    try:
        if not proc.wait_ports(ports, timeout=30):
            log("  Xray не запустился: " + proc.tail_log(3))
            return False
        with ThreadPoolExecutor(workers) as ex:
            list(ex.map(fn, zip(servers, ports)))
        return True
    finally:
        proc.stop()


def test_servers(servers, timeout=5, geo=True, batch=1000, log=print, enough=None, cancel=None):
    """Проверка в два шага: быстрый пинг всех сразу, затем загрузка 256 КБ через живых.
    Проставляет s['ping'] и s['speed'] (None = не работает)."""
    xray.ensure_xray(log)
    cfg_path = xray.CORE_DIR / "tester_check.json"
    alive = 0
    for i in range(0, len(servers), batch):
        if cancel and cancel.is_set():
            break
        for s in servers[i:i + batch]:
            s["ping"] = s["speed"] = None
        chunk = _valid_subset(servers[i:i + batch], cfg_path)
        if not chunk:
            continue
        def ping_one(sp):
            sp[0]["ping"] = ping(proxy_opener(sp[1]), timeout)

        def traffic_one(sp):
            _check_traffic(sp[0], sp[1], geo)

        if not _run_on_tester(chunk, ping_one, len(chunk), log):
            continue
        # загрузку проверяем в свежем Xray только с ответившими: после пинга тысяч серверов
        # в старом процессе висят недозвонившиеся соединения и душат канал
        pinged = [s for s in chunk if s["ping"]]
        _run_on_tester(pinged, traffic_one, SPEED_WORKERS, log)
        ok = sum(1 for s in chunk if s["ping"])
        alive += ok
        log(f"  проверено {min(i + batch, len(servers))}/{len(servers)}: отвечают {len(pinged)}, "
            f"качают {ok} (всего рабочих {alive})")
        if enough and alive >= enough:
            break
    cfg_path.unlink(missing_ok=True)
    return [s for s in servers if s.get("ping")]


def recheck(servers, log=print, cancel=None):
    """Перепроверка списка: пинг + загрузка у всех, затем точная скорость у лучших
    (грубые цифры при 32 параллельных загрузках не годятся для выбора в АВТО)."""
    alive = test_servers(servers, geo=False, log=log, cancel=cancel)
    measure_all(alive, log=log)
    return alive


def _geo_fallback(servers):
    """Для серверов без гео по выходному IP — берём гео самого сервера или флаг из названия."""
    todo = [s for s in servers if not s.get("country_code")]
    if not todo:
        return
    ips = {}
    for s in todo:
        try:
            ips[s["host"]] = socket.gethostbyname(s["host"])
        except (OSError, UnicodeError):
            pass
    unique_ips, geo = sorted(set(ips.values())), {}
    for i in range(0, len(unique_ips), 100):  # ip-api принимает до 100 адресов за раз
        try:
            body = json.dumps([{"query": ip} for ip in unique_ips[i:i + 100]]).encode()
            req = urllib.request.Request("http://ip-api.com/batch?fields=status,country,countryCode,city,query",
                                         data=body, headers={"User-Agent": xray.UA})
            geo.update({d["query"]: d for d in json.loads(urllib.request.urlopen(req, timeout=20).read())
                        if d.get("status") == "success"})
        except Exception:  # noqa: BLE001 — нет гео, возьмём флаг из названия
            pass
    for s in todo:
        d = geo.get(ips.get(s["host"]), {})
        s["country_code"] = d.get("countryCode") or links.flag_country(s.get("remark", "")) or "XX"
        s["country"] = d.get("country", "")
        s["city"] = d.get("city", "")


def rank(s):
    """Порядок в списке: зарубежные по скорости, потом с выходом в России (заблокированные сайты
    через них не открываются), обход белых списков — в самом конце."""
    return (bool(s.get("white")), s.get("country_code") == "RU", -(s.get("speed") or 0), s.get("ping") or 10**9)


def _robust(s):
    """Для «⚡ АВТО» — только прямые зашифрованные соединения: tcp/xhttp + reality/tls (и hysteria2).
    gRPC на бесплатных серверах часто не может установить соединение, WS обычно идёт через Cloudflare,
    который рвёт длинные загрузки, а нешифрованные легко режет DPI — на пинг они отвечают, а трафик теряют."""
    if s["proto"] == "hysteria2":
        return True
    ss = s["outbound"].get("streamSettings", {})
    return ss.get("network", "tcp") in ("tcp", "xhttp") and ss.get("security") in ("reality", "tls")


def auto_pool(servers, size=30, for_chain=False, basic_only=False, prefer_stable=True):
    """Самые быстрые рабочие серверы для «⚡ АВТО». Выход в России не открывает заблокированные сайты,
    белые списки нужны для другого, hysteria2 (UDP) не встаёт в цепочку и не везде поддерживается.
    prefer_stable — сначала те, что выдержали длинную загрузку (если таких набралось хотя бы 8)."""
    alive = [s for s in servers if s.get("ping") and s.get("country_code") != "RU" and not s.get("white")
             and not ((for_chain or basic_only) and s["proto"] == "hysteria2") and _robust(s)]
    if sum(1 for s in alive if near(s)) >= 8:
        alive = [s for s in alive if near(s)]
    if prefer_stable and sum(1 for s in alive if s.get("stable")) >= 8:
        alive = [s for s in alive if s.get("stable")]
    return sorted(alive, key=lambda s: (-(s.get("speed") or 0), s["ping"]))[:size]


def select(alive, target):
    alive = sorted(alive, key=rank)
    max_per_country = max(20, target // 5)  # чтобы не было всех серверов в одной Германии
    picked, used, per_country, per_exit = [], set(), {}, {}
    for strict in (True, False):
        for s in alive:
            if len(picked) >= target:
                break
            if id(s) in used:
                continue
            cc, exit_ip = s.get("country_code") or "XX", s.get("exit_ip")
            # у одного сервера бывает 5–6 почти одинаковых ссылок — берём не больше двух на выходной IP
            if strict and ((not s["white"] and per_country.get(cc, 0) >= max_per_country)
                           or (exit_ip and per_exit.get(exit_ip, 0) >= MAX_PER_EXIT_IP)):
                continue
            picked.append(s)
            used.add(id(s))
            per_country[cc] = per_country.get(cc, 0) + 1
            if exit_ip:
                per_exit[exit_ip] = per_exit.get(exit_ip, 0) + 1
    return sorted(picked, key=rank)


def save(servers, full=False):
    """full=True — после полного сбора: запоминаем время, чтобы расписание знало, когда пора снова."""
    fields = ("name", "proto", "ping", "speed", "stable", "country_code", "country", "city", "exit_ip", "white",
              "link")
    now = datetime.now().isoformat(timespec="seconds")
    data = {"updated": now, "collected": now if full else _stamp("collected"),
            "servers": [{k: s.get(k) for k in fields} for s in servers]}
    SERVERS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    SUB_FILE.write_text("\n".join(links.rename(s["link"], s["name"]) for s in servers) + "\n",
                        encoding="utf-8")


def _stamp(field):
    try:
        return json.loads(SERVERS_FILE.read_text(encoding="utf-8")).get(field)
    except (OSError, ValueError):
        return None


def updated_at(field="updated"):
    """Когда список последний раз проверялся ("updated") или собирался полностью ("collected"), unix time."""
    try:
        return datetime.fromisoformat(_stamp(field)).timestamp()
    except (TypeError, ValueError):
        return 0


LOCK = xray.CORE_DIR / "collect.lock"


@contextlib.contextmanager
def lock():
    """Чтобы программа и планировщик не проверяли и не писали список одновременно."""
    xray.CORE_DIR.mkdir(exist_ok=True)
    if LOCK.exists() and time.time() - LOCK.stat().st_mtime > 3600:
        LOCK.unlink(missing_ok=True)  # хвост от упавшего запуска
    try:
        fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise RuntimeError("проверка серверов уже идёт (программа или планировщик) — попробуй позже") from None
    os.write(fd, str(os.getpid()).encode())
    os.close(fd)
    try:
        yield
    finally:
        LOCK.unlink(missing_ok=True)


def quick_check(log=print):
    """Лёгкая ежечасная проверка (~1 мин, ~10–40 МБ): пинг всех серверов — умершие сразу пропадают из
    подписки (в Happ не висят «н/д»), а пулу «⚡ АВТО» перемеряем скорость на 1 МБ. Новых не ищем."""
    with lock():
        xray.ensure_xray(log)  # в облаке ядра ещё нет — скачается при первом запуске (потом из кэша)
        servers = load()
        # из облака (США) многие серверы белых списков не отвечают нарочно — они пускают только российских
        # пользователей, поэтому их статус облако не трогает; обновляет его полное обслуживание
        check = [s for s in servers if not (IN_CLOUD and s.get("white"))]
        for s in check:
            s["ping"] = None

        def ping_one(sp):
            sp[0]["ping"] = ping(proxy_opener(sp[1]), 5)
        for i in range(0, len(check), 1000):
            _run_on_tester(_valid_subset(check[i:i + 1000], xray.CORE_DIR / "tester_check.json"),
                           ping_one, 1000, log)
        (xray.CORE_DIR / "tester_check.json").unlink(missing_ok=True)
        alive = [s for s in servers if s["ping"]]
        def speed_one(sp):
            mbps = speed(proxy_opener(sp[1]), size=1024 * 1024, timeout=20)
            if mbps:
                sp[0]["speed"] = mbps
            else:
                sp[0]["stable"] = False  # не скачал 1 МБ — из АВТО выбывает до следующей полной проверки
        _run_on_tester(auto_pool(alive, ENDURANCE_TOP), speed_one, 3, log)
        save(sorted(servers, key=rank))
        log(f"Лёгкая проверка: отвечают {len(alive)} из {len(servers)}, в АВТО {len(auto_pool(alive, 30))}")
        return alive


def load():
    if not SERVERS_FILE.exists():
        return []
    servers = json.loads(SERVERS_FILE.read_text(encoding="utf-8"))["servers"]
    for s in servers:
        s.update(links.parse(s["link"]), link=s["link"], key=link_key(s["link"]))
    return servers


def link_network(link):
    """Транспорт по ссылке без полного разбора: tcp, ws, xhttp, grpc, httpupgrade, udp."""
    scheme = link.split("://", 1)[0].lower()
    if scheme == "vmess":
        try:
            net = json.loads(links.b64decode(link[8:].split("#")[0])).get("net") or "tcp"
        except (ValueError, TypeError, AttributeError):
            return ""
    elif scheme in ("vless", "trojan"):
        try:
            net = (parse_qs(urlsplit(link.split("#")[0]).query).get("type") or ["tcp"])[-1]
        except ValueError:  # битая ссылка вроде [1.2.3.4]:443
            return ""
    else:
        return "udp" if scheme in ("hysteria2", "hy2") else "tcp"
    net = str(net).lower()
    return {"splithttp": "xhttp", "raw": "tcp"}.get(net, net)


def collect(target=TARGET, log=print, cancel=None, max_minutes=25, networks=None, only_white=False):
    """Собирает рабочие серверы. networks=("xhttp", "ws") или only_white=True — не пересобирать
    список, а добавить к нему новые серверы только с этими транспортами / только обход белых списков."""
    with lock():
        return _collect(target, log, cancel, max_minutes, networks, only_white)


def _collect(target, log, cancel, max_minutes, networks, only_white):
    cancel = cancel or threading.Event()
    started = time.time()
    xray.ensure_xray(log)
    log("Качаю списки бесплатных серверов...")
    prio, rest = gather(log)
    try:  # уже найденные рабочие серверы перепроверяем первыми, чтобы не потерять
        old = load()
    except (OSError, ValueError, KeyError):
        old = []
    old_keys = {s["key"] for s in old}
    fresh = [c for c in prio + rest if c["key"] not in old_keys]
    adding = bool(networks or only_white)
    if adding:  # режим «добавить»: текущий список не трогаем
        if only_white:
            fresh = [c for c in fresh if c["white"]]
            what = "обход белых списков"
        else:
            order = {n: i for i, n in enumerate(networks)}
            fresh = [c for c in fresh if link_network(c["link"]) in order]
            fresh.sort(key=lambda c: order[link_network(c["link"])])  # внутри — прежний порядок источников
            what = f"транспорт {' / '.join(networks)}"
        candidates, enough = fresh, max(0, target - len(old))
        log(f"Добавляю к {len(old)} серверам новые ({what}): кандидатов {len(candidates)}, места в списке {enough}")
    else:
        candidates = old + fresh
        enough = target + target // 10  # небольшой запас, чтобы было из чего выбирать
        log(f"Кандидатов: {len(candidates)}. Сначала подборки для РФ, потом агрегаторы, пока не наберём {enough}")
    alive, step = [], 3000

    def prepare(part):  # старые серверы уже разобраны, новые разбираем только сейчас — экономит память
        return tcp_filter([p for p in part if "outbound" in p] + parse_all(p for p in part if "outbound" not in p))

    with ThreadPoolExecutor(1) as prefetch:  # следующую порцию готовим, пока проверяем текущую
        nxt = prefetch.submit(prepare, candidates[:step])
        for i in range(0, len(candidates), step):
            if cancel.is_set() or len(alive) >= enough:
                break
            if time.time() - started > max_minutes * 60:
                log(f"Лимит {max_minutes} мин: дальше в агрегаторах почти одни мёртвые серверы, заканчиваю")
                break
            try:
                part = nxt.result()
                nxt = prefetch.submit(prepare, candidates[i + step:i + 2 * step])
                alive += test_servers(part, log=log, enough=enough - len(alive), cancel=cancel)
            except Exception as e:  # noqa: BLE001 — не теряем уже найденные серверы из-за одной кривой ссылки
                log(f"Ошибка при проверке ({type(e).__name__}: {e}), сохраняю то, что уже нашлось")
                break
            log(f"Проверено {min(i + step, len(candidates))} из {len(candidates)} ссылок, "
                f"рабочих {len(alive)}, прошло {int(time.time() - started) // 60} мин")
    if cancel.is_set():
        log("Отменено.")
        return []
    _geo_fallback(alive)
    for s in alive + (old if adding else []):  # «обход белых списков» — только с выходом за границей,
        if s["white"] and s.get("country_code") == "RU":  # с выходом в России это обычный сервер
            s["white"] = False
            s["name"] = None  # переименуем без «ОБХОД БЕЛЫХ СПИСКОВ»
    new = select(alive, enough if adding else target)
    # при проверке 32 загрузки шли разом и делили канал — лучшим меряем скорость точно
    picked = sorted(old + new if adding else new, key=rank)
    measure_all(picked, log=log)
    picked.sort(key=rank)
    names.assign_names(picked)
    save(picked, full=not adding)
    extra = f" (новых: {len(new)})" if adding else ""
    log(f"Готово: {len(picked)} рабочих серверов сохранено в {SERVERS_FILE.name}{extra}")
    return picked

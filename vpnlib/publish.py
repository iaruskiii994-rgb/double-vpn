"""Подписка в интернете: секретный GitHub Gist, который работает на любом устройстве и в любой сети.

Доступ к GitHub берётся из входа, которым пользуется git (Git Credential Manager), — токен нигде не
сохраняется. Если git не залогинен, можно один раз вставить свой токен с правом `gist`.
Программа сама обновляет Gist после каждой проверки/сбора, а Happ подтягивает изменения.
"""
import json
import os
import subprocess
import urllib.error
import urllib.request

from . import collector, share, xray

CONF = xray.CORE_DIR / "github.json"
# для Happ: Xray JSON с «⚡ АВТО» первым. double_vpn.txt — первая выданная ссылка, она у многих уже
# добавлена в Happ, поэтому в ней теперь тоже JSON с АВТО
HAPP_FILENAMES = ("happ.json", "double_vpn.txt")
LINKS_FILENAME = "links.txt"  # обычные ссылки — для любых других приложений
API = "https://api.github.com"
TOKEN_URL = "https://github.com/settings/tokens/new?scopes=gist&description=DOUBLE%20VPN"


def load_conf():
    try:
        conf = json.loads(CONF.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        conf = {}
    if os.environ.get("GIST_ID"):  # в облаке GitHub адрес подписки — в секрете, а не в публичном коде
        conf.setdefault("gist_id", os.environ["GIST_ID"])
    return conf


def public_url():
    return load_conf().get("raw_url", "")


def happ_url():
    return load_conf().get("happ_url", "")


def happ_link(url):
    """Ссылка, которая на телефоне сразу открывает Happ и добавляет подписку."""
    return f"happ://add/{url}"


def git_token():
    """Токен GitHub из Git Credential Manager (тот же вход, что у git). Окно входа не открываем."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
    try:
        r = subprocess.run(["git", "credential", "fill"], input="protocol=https\nhost=github.com\n\n",
                           capture_output=True, text=True, timeout=30, env=env, creationflags=xray.NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return next((l[9:] for l in r.stdout.splitlines() if l.startswith("password=")), "")


def _api(method, path, token, payload=None):
    req = urllib.request.Request(
        API + path, method=method, data=json.dumps(payload).encode() if payload else None,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": xray.UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _explain(e):
    if e.code == 401:
        return RuntimeError("GitHub не принял токен — проверь, что он скопирован целиком и не просрочен")
    if e.code == 403:
        return RuntimeError("у токена нет права gist — создай новый с галочкой «gist»")
    return RuntimeError(f"GitHub ответил ошибкой {e.code}")


def publish(token=None):
    """Создаёт или обновляет Gist с живыми серверами. Возвращает (ссылка, число серверов)."""
    conf = load_conf()
    user_token = (token or conf.get("token") or "").strip()  # вставленный вручную — храним
    # в облаке GitHub — из секрета GIST_TOKEN, на ПК — из входа git (берём каждый раз заново и не храним)
    token = user_token or os.environ.get("GIST_TOKEN", "") or git_token()
    if not token:
        raise RuntimeError("нет доступа к GitHub: войди в GitHub через git или вставь токен")
    text, count = share.subscription_text()
    happ, _ = share.happ_json()
    files = {LINKS_FILENAME: {"content": text}, **{name: {"content": happ} for name in HAPP_FILENAMES}}
    gist = None
    try:
        if conf.get("gist_id"):
            try:
                gist = _api("PATCH", f"/gists/{conf['gist_id']}", token, {"files": files})
            except urllib.error.HTTPError as e:
                if e.code != 404:  # Gist удалили или он в другом аккаунте — создадим новый
                    raise
        if gist is None:
            gist = _api("POST", "/gists", token, {"description": "DOUBLE VPN — подписка", "public": False,
                                                   "files": files})
    except urllib.error.HTTPError as e:
        raise _explain(e) from e
    # ссылка без хэша коммита всегда отдаёт последнюю версию файла
    base = f"https://gist.githubusercontent.com/{gist['owner']['login']}/{gist['id']}/raw/"
    raw_url = base + LINKS_FILENAME
    new_conf = {**conf, "gist_id": gist["id"], "raw_url": raw_url, "happ_url": base + HAPP_FILENAMES[0]}
    new_conf.pop("token", None)
    if user_token:
        new_conf["token"] = user_token
    xray.CORE_DIR.mkdir(exist_ok=True)
    CONF.write_text(json.dumps(new_conf), encoding="utf-8")
    return raw_url, count


def cloud_repo():
    """Репозиторий GitHub, где подписку обновляет облако (GitHub Actions), например "user/double-vpn"."""
    return load_conf().get("cloud_repo", "")


def in_cloud():
    return bool(os.environ.get("GITHUB_ACTIONS"))


def configured():
    """Должна ли ЭТА машина обновлять подписку в интернете. Если подписку ведёт облако —
    компьютер её не трогает (иначе они перезаписывали бы друг друга), а только забирает список оттуда."""
    return bool(load_conf().get("gist_id")) and (not cloud_repo() or in_cloud())


def sync_from_cloud():
    """Забирает свежий список серверов, который облако проверило последним. Возвращает число серверов."""
    url = f"https://raw.githubusercontent.com/{cloud_repo()}/main/servers.json"
    data = json.loads(xray.http_get(url, timeout=30))
    if not isinstance(data.get("servers"), list) or not data["servers"]:
        raise RuntimeError("в облаке пустой список")
    collector.SERVERS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return len(data["servers"])

"""Сбор рабочих бесплатных серверов из консоли.

    python collect.py                 # собрать список заново (до 1000 серверов)
    python collect.py --refresh       # для планировщика (раз в час): лёгкая проверка ~1 мин — умершие пропадают
                                      # из подписки; раз в 6 ч — полное обслуживание ~15 мин с добором новых.
                                      # Пишет core/refresh.log
    python collect.py --add xhttp,ws  # добавить к текущему списку серверы с транспортом xhttp и WS
    python collect.py --white         # добавить обход белых списков с выходом за границей
"""
import argparse
import os
import sys
import time
from datetime import datetime

from vpnlib import collector, publish, xray

FULL_EVERY_HOURS = 6  # полное обслуживание с добором новых серверов — не чаще, бережём трафик

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", type=int, default=collector.TARGET, help="сколько серверов максимум")
    ap.add_argument("--refresh", action="store_true", help="быстрое обслуживание списка для расписания")
    ap.add_argument("--add", help="транспорты через запятую: xhttp,ws,grpc,tcp")
    ap.add_argument("--white", action="store_true", help="добавить обход белых списков (выход за границей)")
    ap.add_argument("--minutes", type=int, default=25, help="лимит времени на проверку")
    args = ap.parse_args()

    cloud = bool(os.environ.get("GITHUB_ACTIONS"))  # в облаке GitHub лог видно прямо в Actions
    if args.refresh and not cloud:  # по расписанию на ПК консоли нет — пишем в файл
        xray.CORE_DIR.mkdir(exist_ok=True)
        out = open(xray.CORE_DIR / "refresh.log", "a", encoding="utf-8")
    else:
        out = sys.stdout
        out.reconfigure(encoding="utf-8", errors="replace")
    if args.refresh:
        args.minutes = 12

    def log(msg):
        print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}" if args.refresh else msg, file=out, flush=True)

    networks = tuple(n.strip() for n in args.add.split(",")) if args.add else None
    try:
        full_due = time.time() - collector.updated_at("collected") >= FULL_EVERY_HOURS * 3600
        if args.refresh and not full_due and os.environ.get("FORCE_FULL") != "true":
            servers = collector.quick_check(log=log)
        else:
            servers = collector.collect(target=args.target, networks=networks, max_minutes=args.minutes,
                                        only_white=args.white, log=log)
    except RuntimeError as e:  # уже идёт другая проверка
        log(f"Пропуск: {e}")
        sys.exit(0)
    if not args.refresh:
        for s in servers:
            log(f"{s.get('speed') or '✗':>5} Мбит/с {s.get('ping') or '✗':>5} мс  {s['proto']:<9} {s['name']}")
    if publish.configured():  # подписка в интернете — обновляем сразу
        url, count = publish.publish()
        log(f"Подписка в интернете обновлена ({count} серверов)" + ("" if cloud else f": {url}"))  # логи облака публичны

"""DOUBLE VPN — бесплатный VPN на Python (ядро Xray). Запуск: python vpn.py"""
import ctypes
import queue
import sys
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk

from vpnlib import collector, links, names, publish, qr, share, sysproxy, xray

OFF = "— выключен —"
AUTO = "auto"  # id строки «⚡ АВТО» в списке
AUTO_POOL = 30  # из скольких самых быстрых серверов выбирает АВТО
REFRESH_HOURS = 1  # лёгкая проверка: умершие серверы пропадают из подписки
FULL_REFRESH_HOURS = 6  # полное обслуживание с добором новых серверов
BG, FG, ACCENT, WHITE_ROW = "#101418", "#e8eef2", "#2ecc71", "#1d3b2a"


class App:
    def __init__(self, root):
        self.root = root
        self.servers = []
        self.client = None
        self.busy = None  # поток сбора/проверки
        self.cancel = threading.Event()
        self.jobs = queue.Queue()
        self.share = share.SubscriptionServer()
        self.sort_col, self.sort_rev = "n", False

        k = root.winfo_fpixels("1i") / 96  # масштаб экрана (125%, 150%...)
        root.title("DOUBLE VPN")
        root.geometry(f"{int(980 * k)}x{int(680 * k)}")
        root.configure(bg=BG)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=FG, fieldbackground="#1a2026")
        style.configure("Treeview", background="#161b20", foreground=FG, rowheight=int(24 * k),
                        fieldbackground="#161b20")
        style.map("Treeview", background=[("selected", "#2d6cdf")])
        style.configure("Treeview.Heading", background="#20272e", foreground=FG)
        style.configure("TButton", background="#20272e", padding=6)
        style.configure("TMenubutton", background="#20272e", padding=6)
        style.configure("Go.TButton", background="#1f7a45", font=("Segoe UI", 10, "bold"))
        style.configure("TCheckbutton", background=BG, foreground=FG, indicatorsize=int(13 * k))
        style.map("TCheckbutton", background=[("active", BG)])
        style.configure("TRadiobutton", background=BG, foreground=FG, indicatorsize=int(13 * k))
        style.map("TRadiobutton", background=[("active", BG)])
        style.configure("TCombobox", arrowsize=int(12 * k))
        style.map("TCombobox", fieldbackground=[("readonly", "#1a2026")], foreground=[("readonly", FG)],
                  selectbackground=[("readonly", "#1a2026")], selectforeground=[("readonly", FG)])

        top = tk.Frame(root, bg=BG)
        top.pack(fill="x", padx=12, pady=(10, 4))
        tk.Label(top, text="DOUBLE VPN", font=("Segoe UI Black", 20), bg=BG, fg=ACCENT).pack(side="left")
        self.status = tk.Label(top, text="● Отключено", font=("Segoe UI", 11, "bold"), bg=BG, fg="#e74c3c")
        self.status.pack(side="right")

        bar = tk.Frame(root, bg=BG)
        bar.pack(fill="x", padx=12, pady=4)
        ttk.Button(bar, text="▶ ПОДКЛЮЧИТЬ", style="Go.TButton", command=self.connect).pack(side="left")
        ttk.Button(bar, text="■ ОТКЛЮЧИТЬ", command=self.disconnect).pack(side="left", padx=4)
        ttk.Button(bar, text="⟳ Проверить серверы", command=self.recheck).pack(side="left", padx=4)
        collect_btn = ttk.Menubutton(bar, text="⬇ Собрать ▾")
        collect_menu = tk.Menu(collect_btn, tearoff=0)
        collect_menu.add_command(label=f"Собрать заново (до {collector.TARGET})", command=self.recollect)
        collect_menu.add_command(label="➕ Добавить серверы xhttp и WS",
                                 command=lambda: self.recollect(("xhttp", "ws")))
        collect_menu.add_command(label="➕ Добавить обход белых списков (выход за границей)",
                                 command=lambda: self.recollect(only_white=True))
        collect_btn["menu"] = collect_menu
        collect_btn.pack(side="left", padx=4)
        ttk.Button(bar, text="📋 Ссылка", command=self.copy_link).pack(side="left", padx=4)
        ttk.Button(bar, text="📱 Другие устройства", command=self.share_dialog).pack(side="left", padx=4)
        tk.Label(bar, text="Поиск:", bg=BG, fg=FG).pack(side="left", padx=(16, 4))
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_: self.refresh())
        ttk.Entry(bar, textvariable=self.search, width=22).pack(side="left")

        opts = tk.Frame(root, bg=BG)
        opts.pack(fill="x", padx=12, pady=4)
        self.use_sysproxy = tk.BooleanVar(value=sysproxy.SUPPORTED)
        self.ru_direct = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Системный прокси Windows", variable=self.use_sysproxy).pack(side="left")
        ttk.Checkbutton(opts, text="Российские сайты напрямую", variable=self.ru_direct).pack(side="left", padx=12)
        tk.Label(opts, text="DOUBLE VPN — сначала через:", bg=BG, fg=FG).pack(side="left", padx=(12, 4))
        self.hop = ttk.Combobox(opts, state="readonly", width=42, values=[OFF])
        self.hop.set(OFF)
        self.hop.pack(side="left")
        # появляется, если интернет уже идёт через чужой VPN (TUN у Happ и т.п.)
        self.warn = tk.Label(root, bg="#5a1e1e", fg="#ffd0d0", font=("Segoe UI", 10, "bold"),
                             anchor="w", justify="left", padx=8, pady=4, wraplength=int(940 * k))

        cols = {"n": ("№", 45), "name": ("Название", 380), "proto": ("Протокол", 80), "tr": ("Транспорт", 115),
                "country": ("Страна", 150), "ping": ("Пинг, мс", 70), "speed": ("Мбит/с", 65)}
        frame = tk.Frame(root, bg=BG)
        frame.pack(fill="both", expand=True, padx=12, pady=4)
        self.tree = ttk.Treeview(frame, columns=list(cols), show="headings", selectmode="browse")
        for c, (title, w) in cols.items():
            self.tree.heading(c, text=title, command=lambda c=c: self.sort_by(c))
            self.tree.column(c, width=int(w * k), anchor="w" if c in ("name", "country") else "center")
        self.tree.tag_configure("white", background=WHITE_ROW)
        self.tree.tag_configure("dead", foreground="#6b7680")
        self.tree.tag_configure("auto", background="#3a3312", foreground="#f1c40f", font=("Segoe UI", 10, "bold"))
        sb = ttk.Scrollbar(frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda e: self.connect())

        bottom = tk.Frame(root, bg=BG)
        bottom.pack(fill="x", padx=12)
        tk.Label(bottom, text=f"Для других программ: SOCKS5 127.0.0.1:{xray.SOCKS_PORT}   HTTP 127.0.0.1:{xray.HTTP_PORT}"
                              f"   •   зелёные строки — {names.WHITE_BRAND}",
                 bg=BG, fg="#8899a6").pack(side="left")
        # бесплатные серверы умирают за дни — без обновления подписка у друзей превращается в «н/д»
        self.auto_refresh = tk.BooleanVar(value=True)
        ttk.Checkbutton(bottom, text="Автообновление каждый час" + (" (из облака GitHub)" if publish.cloud_repo()
                                                                   else " серверов и подписки"),
                        variable=self.auto_refresh).pack(side="right")
        self.log_box = tk.Text(root, height=7, bg="#0b0e11", fg="#9fb3c8", relief="flat", font=("Consolas", 9))
        self.log_box.pack(fill="x", padx=12, pady=(4, 10))

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(100, self.pump)
        sysproxy.restore()  # если прошлый запуск вылетел с включённым прокси
        self.load()
        if not self.servers:
            self.log(f"Серверов ещё нет — собираю {collector.TARGET} рабочих (займёт несколько минут)...")
            self.recollect()
        threading.Thread(target=self.check_other_vpn, daemon=True).start()
        self.last_cloud_sync = 0
        root.after(5_000 if publish.cloud_repo() else 60_000, self.refresh_tick)

    # ---------- служебное ----------
    def ui(self, fn, *args):
        """Выполнить fn в потоке интерфейса (из фоновых потоков)."""
        self.jobs.put((fn, args))

    def pump(self):
        while not self.jobs.empty():
            fn, args = self.jobs.get()
            fn(*args)
        self.root.after(100, self.pump)

    def log(self, msg):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    def tlog(self, msg):
        self.ui(self.log, msg)

    def run_bg(self, target, done):
        if self.busy and self.busy.is_alive():
            messagebox.showinfo("DOUBLE VPN", "Подожди, предыдущая операция ещё идёт")
            return
        self.cancel.clear()

        def work():
            try:
                result = target()
            except Exception as e:  # noqa: BLE001 — показываем любую ошибку в логе
                self.tlog(f"Ошибка: {e}")
                return
            self.ui(done, result)

        self.busy = threading.Thread(target=work, daemon=True)
        self.busy.start()

    def refresh_tick(self):
        """Раз в 10 минут: если список старше REFRESH_HOURS — тихо перепроверить, добрать и опубликовать.
        Если подписку ведёт облако GitHub — просто забрать оттуда свежий список."""
        self.root.after(10 * 60_000, self.refresh_tick)
        if not self.auto_refresh.get() or (self.busy and self.busy.is_alive()):
            return
        if publish.cloud_repo():
            if time.time() - self.last_cloud_sync >= REFRESH_HOURS * 3600:
                self.last_cloud_sync = time.time()
                self.run_bg(publish.sync_from_cloud,
                            lambda n: (self.load(), self.log(f"Свежий список из облака GitHub: {n} серверов")))
            return
        if time.time() - collector.updated_at() < REFRESH_HOURS * 3600:
            return  # планировщик Windows или прошлый запуск уже проверили
        if time.time() - collector.updated_at("collected") >= FULL_REFRESH_HOURS * 3600:
            self.log("Автообновление: перепроверяю серверы, добираю новые и обновляю подписку (~15 мин)...")
            job = lambda: collector.collect(log=self.tlog, cancel=self.cancel, max_minutes=12)  # noqa: E731
        else:
            self.log("Автообновление: лёгкая проверка, умершие серверы уходят из подписки (~1 мин)...")
            job = lambda: collector.quick_check(log=self.tlog)  # noqa: E731
        self.run_bg(job, lambda _: (self.load(), self.auto_publish()))

    def check_other_vpn(self):
        name = sysproxy.other_vpn()

        def show():
            if name:
                self.warn.configure(text=f"⚠ Интернет сейчас идёт через «{name}». С ним трафик пойдёт через два VPN "
                                         f"подряд — медленно, а проверка серверов врёт. Выключи его (или его TUN-режим).")
                self.warn.pack(fill="x", padx=12, pady=(0, 4), after=self.hop.master)
            else:
                self.warn.pack_forget()
        self.ui(show)

    # ---------- список ----------
    def load(self):
        try:
            self.servers = collector.load()
        except (OSError, ValueError, KeyError) as e:
            self.log(f"Не удалось прочитать servers.json: {e}")
            self.servers = []
        # hysteria2 работает по UDP/QUIC и в цепочку не встаёт
        self.hop.configure(values=[OFF] + [s["name"] for s in self.servers if s["proto"] != "hysteria2"])
        self.refresh()
        if self.servers:
            self.log(f"Загружено серверов: {len(self.servers)}")

    def sort_by(self, col):
        self.sort_rev = not self.sort_rev if self.sort_col == col else False
        self.sort_col = col
        self.refresh()

    def auto_pool(self, for_chain=False):
        return collector.auto_pool(self.servers, AUTO_POOL, for_chain=for_chain)

    def refresh(self):
        q = self.search.get().strip().upper()
        rows = [(i, s) for i, s in enumerate(self.servers)
                if not q or q in s["name"] or q in s["proto"].upper() or q in links.transport(s).upper()
                or q in (s.get("country_code") or "")]
        key = {"n": lambda r: r[0], "name": lambda r: r[1]["name"], "proto": lambda r: r[1]["proto"],
               "country": lambda r: r[1].get("country_code") or "",
               "ping": lambda r: r[1].get("ping") or 10**9,
               "speed": lambda r: -(r[1].get("speed") or 0), "tr": lambda r: links.transport(r[1])}[self.sort_col]
        rows.sort(key=key, reverse=self.sort_rev)
        self.tree.delete(*self.tree.get_children())
        pool = self.auto_pool()
        if pool and (not q or q in "АВТО AUTO"):  # всегда первой строкой
            self.tree.insert("", "end", iid=AUTO, tags=("auto",), values=(
                "⚡", f"АВТО — 2 самых стабильных из {len(pool)} быстрых, переключается сам",
                "авто", "", "—", min(s["ping"] for s in pool), max(s.get("speed") or 0 for s in pool)))
        for i, s in rows:
            cc = s.get("country_code") or "??"
            tags = ("white",) if s.get("white") else ()
            if not s.get("ping"):
                tags += ("dead",)
            self.tree.insert("", "end", iid=str(i), tags=tags, values=(
                i + 1, s["name"], s["proto"], links.transport(s), f"{cc} {names.country_word(cc, s.get('country', ''))}",
                s.get("ping") or "✗", s.get("speed") or "✗"))

    def selected(self):
        """Выбранный сервер, AUTO или None."""
        sel = self.tree.selection()
        if not sel:
            return None
        return AUTO if sel[0] == AUTO else self.servers[int(sel[0])]

    # ---------- подключение ----------
    def connect(self):
        s = self.selected()
        if not s:
            messagebox.showinfo("DOUBLE VPN", "Выбери сервер в списке (или ⚡ АВТО в самом верху)")
            return
        hop = next((h for h in self.servers if h["name"] == self.hop.get()), None)
        pool = None
        if s == AUTO:
            pool = [p for p in self.auto_pool(for_chain=bool(hop)) if p is not hop]
            if not pool:
                messagebox.showinfo("DOUBLE VPN", "Нет живых серверов — нажми «Проверить пинг» или «Собрать новые»")
                return
        elif hop is s:
            messagebox.showwarning("DOUBLE VPN", "Первый и второй сервер должны быть разными")
            return
        elif hop and s["proto"] == "hysteria2":
            messagebox.showwarning("DOUBLE VPN", "hysteria2 не работает в режиме DOUBLE VPN — выбери другой сервер")
            return
        self.disconnect(quiet=True)
        try:
            xray.ensure_xray(self.log)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("DOUBLE VPN", f"Не удалось скачать Xray: {e}")
            return
        busy = [p for p in (xray.SOCKS_PORT, xray.HTTP_PORT) if xray.port_open(p)]
        if busy:
            messagebox.showerror("DOUBLE VPN", f"Порт {busy[0]} занят другой программой")
            return
        outbound = [p["outbound"] for p in pool] if pool else s["outbound"]
        cfg = xray.client_config(outbound, hop["outbound"] if hop else None, self.ru_direct.get())
        self.client = xray.XrayProcess(cfg, "client")
        if not self.client.wait_ports([xray.SOCKS_PORT, xray.HTTP_PORT], 8):
            err = self.client.tail_log()
            self.client.stop()
            self.client = None
            self.log(err)
            messagebox.showerror("DOUBLE VPN", "Xray не запустился, подробности в логе")
            return
        if self.use_sysproxy.get():
            sysproxy.enable(xray.HTTP_PORT)
        threading.Thread(target=self.check_other_vpn, daemon=True).start()
        target = f"⚡ АВТО (из {len(pool)} серверов)" if pool else s["name"]
        route = f"{hop['name']}  →  {target}" if hop else target
        self.status.configure(text="● Подключаюсь...", fg="#f1c40f")
        self.log(f"Подключение: {route}")
        client = self.client
        threading.Thread(target=self.check_exit, args=(client, route, pool), daemon=True).start()

    def check_exit(self, client, route, pool=None):
        if pool:
            time.sleep(3)  # даём Xray пропинговать серверы и выбрать лучший
        opener = collector.proxy_opener(xray.HTTP_PORT)
        ms = collector.ping(opener, 12)
        geo = collector.exit_info(opener, 12) if ms else None
        ok = bool(ms)
        if geo:
            info = f"{geo['exit_ip']} ({geo['country_code']}, {geo['city']}), пинг {ms} мс"
            now = next((p for p in pool or [] if p.get("exit_ip") == geo["exit_ip"]), None)
            if now:
                info += f" — сейчас работает {now['name']}"
        else:
            info = f"пинг {ms} мс" if ok else "сервер не отвечает"

        def show():
            if self.client is not client:
                return
            if ok:
                self.status.configure(text="● Подключено", fg=ACCENT)
                self.log(f"Готово! Выход в интернет: {info}")
            else:
                self.status.configure(text="● Сервер не отвечает", fg="#e67e22")
                tip = ("эта пара не стыкуется — выбери другой первый хоп (лучше всего цепляются vless reality)"
                       if " → " in route else "попробуй другой сервер")
                self.log(f"{route}: {info}, {tip}.")
        self.ui(show)

    def disconnect(self, quiet=False):
        if self.client:
            self.client.stop()
            self.client = None
            if not quiet:
                self.log("Отключено")
        sysproxy.restore()
        self.status.configure(text="● Отключено", fg="#e74c3c")

    # ---------- фоновые операции ----------
    def recheck(self):
        if not self.servers:
            return
        self.log("Проверяю все серверы: пинг + загрузка 256 КБ через каждый, у лучших — точная скорость...")
        servers = self.servers
        self.run_bg(lambda: collector.recheck(servers, log=self.tlog, cancel=self.cancel), self.after_recheck)

    def after_recheck(self, alive):
        collector.save(self.servers)
        self.refresh()
        self.log(f"Работают (качают): {len(alive)} из {len(self.servers)}")
        self.auto_publish()

    def recollect(self, networks=None, only_white=False):
        if self.client and self.use_sysproxy.get():
            if not messagebox.askyesno("DOUBLE VPN", "Для честной проверки VPN будет отключён. Продолжить?"):
                return
            self.disconnect()
        self.run_bg(lambda: collector.collect(log=self.tlog, cancel=self.cancel, networks=networks,
                                              only_white=only_white),
                    lambda _: (self.load(), self.auto_publish()))

    def copy_link(self):
        s = self.selected()
        if s == AUTO:
            self.share_dialog()
        elif s:
            self.root.clipboard_clear()
            self.root.clipboard_append(links.rename(s["link"], s["name"]))
            self.log(f"Ссылка скопирована (можно вставить в v2rayN / Hiddify / Happ): {s['name']}")

    # ---------- другие устройства ----------
    def share_dialog(self):
        try:
            self.share.start()
        except OSError as e:
            self.log(f"Раздача по домашней сети недоступна — порт {share.PORT} занят: {e}")
        public, happ = publish.public_url(), publish.happ_url()
        urls = ([(happ, "🌐 для Happ — первым ⚡ АВТО, в конце обход белых списков, флаги стран")] if happ else []) + (
            [(public, "🌐 для других приложений (v2rayNG, Hiddify…) — работает везде")] if public else []) + [
            (u, "🏠 " + label) for u, label in (self.share.urls() if self.share.httpd else [])]
        _, count = share.subscription_body()
        k = self.root.winfo_fpixels("1i") / 96
        win = tk.Toplevel(self.root, bg=BG, padx=int(16 * k), pady=int(12 * k))
        win.title("DOUBLE VPN — другие устройства")
        win.transient(self.root)  # поверх главного окна
        tk.Label(win, text="📱 Подписка для Happ и других устройств", font=("Segoe UI", 13, "bold"),
                 bg=BG, fg=ACCENT).pack(anchor="w")
        tk.Label(win, text=f"{count} живых серверов с названиями, в приложении обновляются сами раз в час",
                 bg=BG, fg=FG).pack(anchor="w", pady=(0, 8))
        if not public:
            self._token_block(win, k)

        url = tk.StringVar(value=urls[0][0] if urls else "")
        canvas = tk.Canvas(win, bg="white", highlightthickness=0)
        for u, label in urls:
            ttk.Radiobutton(win, text=f"{label}\n      {u}", value=u, variable=url,
                            command=lambda: draw()).pack(anchor="w", pady=2)

        def draw():
            try:
                matrix = qr.encode(url.get())
            except ValueError:  # слишком длинная ссылка для QR — остаётся кнопка «Копировать»
                canvas.delete("all")
                return
            cell = max(3, int(240 * k) // (len(matrix) + 8))
            side = cell * (len(matrix) + 8)
            canvas.configure(width=side, height=side)
            canvas.delete("all")
            for y, row in enumerate(matrix):
                for x, dark in enumerate(row):
                    if dark:
                        x0, y0 = (x + 4) * cell, (y + 4) * cell
                        canvas.create_rectangle(x0, y0, x0 + cell, y0 + cell, fill="black", width=0)

        def copy(text, what):
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.log(f"{what} скопирована: {text}")

        if urls:
            canvas.pack(pady=int(10 * k))
            draw()
            buttons = tk.Frame(win, bg=BG)
            buttons.pack()
            ttk.Button(buttons, text="📋 Копировать ссылку",
                       command=lambda: copy(url.get(), "Ссылка на подписку")).pack(side="left", padx=4)
            ttk.Button(buttons, text="📲 Ссылка «добавить в Happ»",
                       command=lambda: copy(publish.happ_link(happ or url.get()), "Ссылка для Happ")
                       ).pack(side="left", padx=4)
        tk.Label(win, justify="left", bg=BG, fg="#9fb3c8", wraplength=int(560 * k), text=(
            "Happ: «+» → «Добавить из буфера» (скопируй ссылку) или «Сканировать QR». Ссылка «добавить в Happ» "
            "(happ://add/…) — отправь её себе в Telegram и нажми на телефоне, Happ сам добавит подписку.\n"
            "v2rayNG / Hiddify / Streisand / v2rayN — так же, через «Добавить подписку».\n"
            "🏠 Домашние ссылки работают, только пока эта программа запущена и телефон в той же Wi-Fi сети. "
            "Если не открываются — разреши Python в брандмауэре Windows для частных и общедоступных сетей.")
                 ).pack(anchor="w", pady=(int(10 * k), 0))

    def _token_block(self, win, k):
        """Первичная настройка ссылки в интернете: через вход git в GitHub или через вставленный токен."""
        box = tk.Frame(win, bg="#17212b", padx=int(10 * k), pady=int(8 * k))
        box.pack(fill="x", pady=(0, 10))
        tk.Label(box, justify="left", bg="#17212b", fg=FG, wraplength=int(540 * k), text=(
            "🌐 Ссылка для любого устройства и любой сети (мобильный интернет, другой город). Программа хранит "
            "подписку в твоём секретном GitHub Gist и сама обновляет её после каждой проверки серверов.")
                 ).pack(anchor="w")

        def create(token=None):
            self.log("Создаю подписку в интернете...")

            def work():
                try:
                    link, n = publish.publish(token)
                except Exception as e:  # noqa: BLE001 — покажем причину в логе
                    self.tlog(f"Не получилось создать ссылку: {e}")
                    return
                self.tlog(f"Готово! Подписка в интернете ({n} серверов): {link}")
                self.ui(lambda: (win.destroy(), self.share_dialog()))
            threading.Thread(target=work, daemon=True).start()

        if publish.git_token():  # GitHub уже подключён через git — токен не нужен
            ttk.Button(box, text="✅ GitHub подключён — создать ссылку", command=create).pack(anchor="w", pady=4)
            return
        tk.Label(box, text="Нужен бесплатный аккаунт GitHub и токен только с правом «gist»:",
                 bg="#17212b", fg=FG).pack(anchor="w")
        ttk.Button(box, text="1) Открыть GitHub и создать токен (галочка «gist» уже стоит)",
                   command=lambda: webbrowser.open(publish.TOKEN_URL)).pack(anchor="w", pady=4)
        row = tk.Frame(box, bg="#17212b")
        row.pack(fill="x")
        tk.Label(row, text="2) Вставь токен:", bg="#17212b", fg=FG).pack(side="left")
        token = tk.StringVar()
        ttk.Entry(row, textvariable=token, show="•", width=44).pack(side="left", padx=6)
        ttk.Button(row, text="Создать ссылку",
                   command=lambda: token.get().strip() and create(token.get())).pack(side="left")

    def auto_publish(self):
        """После проверки/сбора обновляем подписку в интернете, если она настроена."""
        if not publish.configured():
            return

        def work():
            try:
                _, n = publish.publish()
                self.tlog(f"Подписка в интернете обновлена: {n} серверов")
            except Exception as e:  # noqa: BLE001
                self.tlog(f"Не удалось обновить подписку в интернете: {e}")
        threading.Thread(target=work, daemon=True).start()

    def on_close(self):
        self.cancel.set()
        self.disconnect(quiet=True)
        self.share.stop()
        xray.stop_all()
        self.root.destroy()


if __name__ == "__main__":
    if sys.platform == "win32":
        try:  # чёткий шрифт на экранах с масштабом 125%+
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    root = tk.Tk()
    App(root)
    root.mainloop()

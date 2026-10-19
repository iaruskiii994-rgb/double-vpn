"""Придумывает серверам русские названия вида «ТУРБОВПН ГЕРМАНИЯ БЕРЛИН КЛАСИК» и флаги стран."""
import hashlib
import random
import re
import unicodedata

WHITE_BRAND = "ОБХОД БЕЛЫХ СПИСКОВ"
BRANDS = [
    "ТУРБОВПН", "УНЖАЛОСТИНЕТ", "СУПЕРСКОРОСТЬ", "РАКЕТА ВПН", "КОТИК ВПН", "НЕВИДИМКА",
    "БЫСТРЫЙ ОЛЕНЬ", "СВОБОДНЫЙ ИНТЕРНЕТ", "МЕГА ЗАЩИТА", "ХОМЯК СПИД", "БАБУШКИН ВАЙФАЙ",
    "ТУРБО УЛИТКА", "ЖЕЛЕЗНЫЙ ТУННЕЛЬ", "ДЫРКА В ЗАБОРЕ", "КИБЕРКОТ", "БЕСПЛАТНО НАВСЕГДА",
    "ОБХОД БЛОКИРОВОК", "ТИХИЙ ШИФР", "СКОРОСТНОЙ ЁЖ", "ПОДЗЕМНЫЙ ХОД", "ВОЛШЕБНЫЙ КАБЕЛЬ",
    "ХИТРЫЙ ЛИС", "БРОНЕВИК ВПН", "КОСМОС ИНТЕРНЕТ", "АНОНИМУС БАРСУК", "ГИПЕРПРОКСИ",
    "ПЕЛЬМЕНЬ ПРОКСИ", "БОРЩ ВПН", "САМОВАР НЕТ", "МАТРЁШКА ВПН", "БАЛАЛАЙКА ТУННЕЛЬ",
    "ШАПКА НЕВИДИМКА", "КОЛОБОК ВПН", "ЗМЕЙ ГОРЫНЫЧ", "БАБА ЯГА СПИД", "ЖАР ПТИЦА",
    "КОЩЕЙ ПРОКСИ", "ЛЕШИЙ ТУННЕЛЬ", "ДОМОВОЙ ВПН", "КАРТОШКА СПИД", "ШУСТРЫЙ ПИНГВИН",
    "ЛЕТУЧАЯ МЫШЬ", "ЗАБОР НЕ ПОМЕХА", "ИНТЕРНЕТ БЕЗ ГРАНИЦ", "СКАТЕРТЬ САМОБРАНКА", "СОВА НОЧНАЯ",
]
# (порог пинга в мс, варианты «тарифа»)
TIERS = [
    (150, ["ПЛАТИНУМ", "ПРО МАКС", "УЛЬТРА", "ГЕЙМЕР"]),
    (300, ["ПРЕМИУМ", "ПЛАЕР", "ТУРБО", "ГОЛД"]),
    (600, ["КЛАСИК", "СТАНДАРТ", "СТРИМ", "ОПТИМАЛ"]),
    (10**9, ["ЭКОНОМ", "ЛАЙТ", "ЧЕРЕПАХА", "БАЗОВЫЙ"]),
]
SPEED_TIERS = [(15, 0), (5, 1), (1.5, 2), (0, 3)]  # Мбит/с -> номер группы в TIERS
COUNTRIES = {
    "DE": "ГЕРМАНИЯ", "NL": "НИДЕРЛАНДЫ", "FR": "ФРАНЦИЯ", "US": "АМЕРИКА", "GB": "БРИТАНИЯ",
    "JP": "ЯПОНИЯ", "FI": "ФИНЛЯНДИЯ", "SE": "ШВЕЦИЯ", "PL": "ПОЛЬША", "TR": "ТУРЦИЯ",
    "RU": "РОССИЯ", "KZ": "КАЗАХСТАН", "CA": "КАНАДА", "SG": "СИНГАПУР", "HK": "ГОНКОНГ",
    "KR": "КОРЕЯ", "CH": "ШВЕЙЦАРИЯ", "AT": "АВСТРИЯ", "IT": "ИТАЛИЯ", "ES": "ИСПАНИЯ",
    "EE": "ЭСТОНИЯ", "LV": "ЛАТВИЯ", "LT": "ЛИТВА", "CZ": "ЧЕХИЯ", "RO": "РУМЫНИЯ",
    "BG": "БОЛГАРИЯ", "AE": "ЭМИРАТЫ", "IR": "ИРАН", "IN": "ИНДИЯ", "CN": "КИТАЙ",
    "BR": "БРАЗИЛИЯ", "AU": "АВСТРАЛИЯ", "AM": "АРМЕНИЯ", "GE": "ГРУЗИЯ", "MD": "МОЛДОВА",
    "CY": "КИПР", "IE": "ИРЛАНДИЯ", "NO": "НОРВЕГИЯ", "DK": "ДАНИЯ", "BE": "БЕЛЬГИЯ",
    "LU": "ЛЮКСЕМБУРГ", "HU": "ВЕНГРИЯ", "RS": "СЕРБИЯ", "VN": "ВЬЕТНАМ", "TH": "ТАИЛАНД",
    "ID": "ИНДОНЕЗИЯ", "UA": "УКРАИНА", "BY": "БЕЛАРУСЬ", "TW": "ТАЙВАНЬ", "IL": "ИЗРАИЛЬ",
    "GR": "ГРЕЦИЯ", "PT": "ПОРТУГАЛИЯ", "SK": "СЛОВАКИЯ", "SI": "СЛОВЕНИЯ", "HR": "ХОРВАТИЯ",
    "IS": "ИСЛАНДИЯ", "MX": "МЕКСИКА", "AR": "АРГЕНТИНА", "ZA": "ЮАР", "MY": "МАЛАЙЗИЯ",
    "PH": "ФИЛИППИНЫ", "UZ": "УЗБЕКИСТАН", "KG": "КИРГИЗИЯ", "AZ": "АЗЕРБАЙДЖАН",
    "SA": "САУДОВСКАЯ АРАВИЯ", "QA": "КАТАР", "BH": "БАХРЕЙН", "CL": "ЧИЛИ", "NZ": "НОВАЯ ЗЕЛАНДИЯ",
    "AL": "АЛБАНИЯ", "MK": "МАКЕДОНИЯ", "BA": "БОСНИЯ", "ME": "ЧЕРНОГОРИЯ", "PK": "ПАКИСТАН",
    "EG": "ЕГИПЕТ", "CO": "КОЛУМБИЯ", "PE": "ПЕРУ", "MT": "МАЛЬТА", "MN": "МОНГОЛИЯ",
    "KH": "КАМБОДЖА", "JO": "ИОРДАНИЯ", "OM": "ОМАН", "KW": "КУВЕЙТ", "MA": "МАРОККО",
}
CITIES = {
    "Amsterdam": "УМСТЕРДАМ", "Frankfurt am Main": "ФРАНКФУРТ", "Frankfurt": "ФРАНКФУРТ", "Moscow": "МОСКВА",
    "Saint Petersburg": "ПИТЕР", "St Petersburg": "ПИТЕР", "Stockholm": "СТОКГОЛЬМ", "Warsaw": "ВАРШАВА",
    "Tokyo": "ТОКИО", "New York": "НЬЮ-ЙОРК", "Los Angeles": "ЛОС-АНДЖЕЛЕС", "Istanbul": "СТАМБУЛ",
    "Vienna": "ВЕНА", "Prague": "ПРАГА", "Tallinn": "ТАЛЛИН", "Vilnius": "ВИЛЬНЮС", "Singapore": "СИНГАПУР",
    "Hong Kong": "ГОНКОНГ", "Seoul": "СЕУЛ", "Munich": "МЮНХЕН", "Nuremberg": "НЮРНБЕРГ",
    "Dusseldorf": "ДЮССЕЛЬДОРФ", "Zurich": "ЦЮРИХ", "Bucharest": "БУХАРЕСТ", "Almaty": "АЛМАТЫ",
    "Helsinki": "ХЕЛЬСИНКИ", "Paris": "ПАРИЖ", "Berlin": "БЕРЛИН", "London": "ЛОНДОН",
    "City of London": "ЛОНДОН", "Milan": "МИЛАН", "Copenhagen": "КОПЕНГАГЕН", "Brussels": "БРЮССЕЛЬ",
    "Dublin": "ДУБЛИН", "Washington": "ВАШИНГТОН", "Chicago": "ЧИКАГО", "Dallas": "ДАЛЛАС", "Miami": "МАЙАМИ",
    "San Jose": "САН-ХОСЕ", "Seattle": "СИЭТЛ", "Toronto": "ТОРОНТО", "Montreal": "МОНРЕАЛЬ", "Kyiv": "КИЕВ",
    "Minsk": "МИНСК", "Riga": "РИГА", "Sofia": "СОФИЯ", "Belgrade": "БЕЛГРАД", "Yerevan": "ЕРЕВАН",
    "Tbilisi": "ТБИЛИСИ", "Dubai": "ДУБАЙ", "Tehran": "ТЕГЕРАН", "Osaka": "ОСАКА", "Sydney": "СИДНЕЙ",
    "Madrid": "МАДРИД", "Rome": "РИМ", "Novosibirsk": "НОВОСИБ", "Yekaterinburg": "ЕКБ", "Kazan": "КАЗАНЬ",
    "Falkenstein": "ФАЛЬКЕНШТАЙН", "Limburg an der Lahn": "ЛИМБУРГ", "Gravelines": "ГРАВЕЛИН",
    "Roubaix": "РУБЕ", "Strasbourg": "СТРАСБУРГ", "Haarlem": "ХАРЛЕМ", "Naaldwijk": "НАЛДВЕЙК",
    "Sao Paulo": "САН-ПАУЛУ", "São Paulo": "САН-ПАУЛУ", "Chisinau": "КИШИНЁВ", "South Jakarta": "ДЖАКАРТА",
    "Jakarta": "ДЖАКАРТА", "Hillsboro": "ХИЛЛСБОРО", "Phoenix": "ФИНИКС", "Santiago": "САНТЬЯГО",
    "San Francisco": "САН-ФРАНЦИСКО", "St Louis": "СЕНТ-ЛУИС", "Secaucus": "СЕКОКУС", "Orem": "ОРЕМ",
    "Redondo Beach": "РЕДОНДО-БИЧ", "Council Bluffs": "КАУНСИЛ-БЛАФС", "Ashburn": "ЭШБЕРН",
    "Manassas": "МАНАССАС", "Buffalo": "БАФФАЛО", "Fremont": "ФРЕМОНТ", "Siauliai": "ШЯУЛЯЙ",
    "Enschede": "ЭНСХЕДЕ", "Tirana": "ТИРАНА", "Wyszkow": "ВЫШКУВ", "Banqiao": "БАНЬЦЯО",
    "Qingyuan": "ЦИНЪЮАНЬ", "Shenzhen": "ШЭНЬЧЖЭНЬ", "Tung Chung": "ТУНЧУН", "San Po Kong": "САНПОКОНГ",
}
CAPITALS = {
    "DE": "БЕРЛИН", "NL": "УМСТЕРДАМ", "FR": "ПАРИЖ", "US": "НЬЮ-ЙОРК", "GB": "ЛОНДОН",
    "FI": "ХЕЛЬСИНКИ", "SE": "СТОКГОЛЬМ", "PL": "ВАРШАВА", "RU": "МОСКВА", "JP": "ТОКИО",
    "TR": "СТАМБУЛ", "KZ": "АЛМАТЫ", "SG": "СИНГАПУР", "HK": "ГОНКОНГ", "EE": "ТАЛЛИН",
    "LV": "РИГА", "LT": "ВИЛЬНЮС", "CA": "ТОРОНТО", "AT": "ВЕНА", "CH": "ЦЮРИХ",
}
# латиница -> кириллица для городов, которых нет в словаре (сначала двухбуквенные сочетания)
_DIGRAPHS = [("shch", "Щ"), ("sch", "Ш"), ("sh", "Ш"), ("ch", "Ч"), ("zh", "Ж"), ("kh", "Х"), ("ts", "Ц"),
             ("ya", "Я"), ("yu", "Ю"), ("yo", "Ё"), ("ye", "Е"), ("ph", "Ф"), ("th", "Т"), ("oo", "У"),
             ("ee", "И"), ("ck", "К"), ("qu", "КВ")]
_LETTERS = dict(zip("abcdefghijklmnopqrstuvwxyz", ["А", "Б", "К", "Д", "Е", "Ф", "Г", "Х", "И", "ДЖ", "К", "Л",
                                                    "М", "Н", "О", "П", "К", "Р", "С", "Т", "У", "В", "В", "КС",
                                                    "Й", "З"]))


def _ascii(text):
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()


_CITIES_ASCII = {_ascii(k): v for k, v in CITIES.items()}


def to_cyrillic(text):
    """Грубая транслитерация: «Siauliai» -> «СИАУЛИАЙ». Кириллицу оставляет как есть."""
    if re.search("[а-яА-ЯёЁ]", text):
        return " ".join(text.upper().split())
    out, s = [], _ascii(text)
    i = 0
    while i < len(s):
        for lat, cyr in _DIGRAPHS:
            if s.startswith(lat, i):
                out.append(cyr)
                i += len(lat)
                break
        else:
            ch = s[i]
            if ch == "y" and 0 < i and s[i - 1] not in "aeiou ":
                out.append("И")  # y после согласной читается как «и»
            else:
                out.append(_LETTERS.get(ch, ch.upper() if ch.isalnum() else " "))
            i += 1
    return " ".join("".join(out).split())


def flag(code):
    """'DE' -> 🇩🇪 (Happ и телефоны показывают это как картинку флага)."""
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha() or code == "XX":
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in code)


def country_word(code, fallback=""):
    return COUNTRIES.get((code or "").upper(), to_cyrillic(fallback) or (code or "").upper() or "НЕИЗВЕСТНО")


def city_word(city, code):
    known = CITIES.get(city) or _CITIES_ASCII.get(_ascii(city or ""))  # «Šiauliai» == «Siauliai»
    return known or to_cyrillic(city or "") or CAPITALS.get((code or "").upper(), "ЦЕНТР")


def tiers_for(s, rnd):
    """Варианты «тарифа» по скорости (или по пингу, если скорость не мерили) в стабильном порядке."""
    if s.get("speed"):
        group = next(g for limit, g in SPEED_TIERS if s["speed"] >= limit)
        variants = TIERS[group][1][:]
    else:
        variants = next(v for limit, v in TIERS if (s.get("ping") or 9999) < limit)[:]
    rnd.shuffle(variants)
    return variants


def is_russian(name):
    return bool(name and re.search("[А-ЯЁ]", name))


def assign_names(servers):
    """servers: список dict с ключами key, white, country_code, country, city, ping, speed.
    Серверы, у которых уже есть русское название (из прошлого сбора), его сохраняют."""
    used = set()
    for s in servers:
        if is_russian(s.get("name")) and s["name"] not in used:
            used.add(s["name"])
        else:
            s["name"] = None
    for s in servers:
        if s["name"]:
            continue
        rnd = random.Random(hashlib.md5(s["key"].encode()).hexdigest())
        place = f"{country_word(s['country_code'], s.get('country', ''))} {city_word(s.get('city', ''), s['country_code'])}"
        tiers = tiers_for(s, rnd)
        if s.get("white"):
            options = [f"{WHITE_BRAND} {place}"] + [f"{WHITE_BRAND} {place} {t}" for t in tiers]
        else:
            brands = BRANDS[:]
            rnd.shuffle(brands)
            options = [f"{b} {place} {tiers[0]}" for b in brands]
        name = next((o for o in options if o not in used), None)
        n = 2
        while name is None:
            candidate = f"{options[0]} {n}"
            name = candidate if candidate not in used else None
            n += 1
        used.add(name)
        s["name"] = name
    return servers

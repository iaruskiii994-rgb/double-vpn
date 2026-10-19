"""Минимальный генератор QR-кодов (байтовый режим, коррекция M, версии 1–6) без сторонних библиотек."""

ECC_PER_BLOCK = [10, 16, 26, 18, 24, 16]  # уровень M, версии 1..6
NUM_BLOCKS = [1, 1, 1, 2, 2, 4]
FORMAT_BITS_M = 0


def _gf_mul(x, y):
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree):
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def _rs_remainder(data, divisor):
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


def _raw_modules(ver):
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        n = ver // 7 + 2
        result -= (25 * n - 10) * n - 55
    return result


def _data_codewords(ver):
    return _raw_modules(ver) // 8 - ECC_PER_BLOCK[ver - 1] * NUM_BLOCKS[ver - 1]


MASKS = [
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
]


class _Grid:
    def __init__(self, ver):
        self.size = ver * 4 + 17
        self.m = [[False] * self.size for _ in range(self.size)]
        self.fn = [[False] * self.size for _ in range(self.size)]

    def set_fn(self, x, y, dark):
        self.m[y][x] = dark
        self.fn[y][x] = True


def _draw_function_patterns(g, ver):
    for i in range(g.size):  # линии синхронизации
        g.set_fn(6, i, i % 2 == 0)
        g.set_fn(i, 6, i % 2 == 0)
    for cx, cy in ((3, 3), (g.size - 4, 3), (3, g.size - 4)):  # искатели
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = cx + dx, cy + dy
                if 0 <= x < g.size and 0 <= y < g.size:
                    g.set_fn(x, y, max(abs(dx), abs(dy)) not in (2, 4))
    if ver >= 2:  # единственный выравнивающий узор для версий 2..6
        c = g.size - 7
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                g.set_fn(c + dx, c + dy, max(abs(dx), abs(dy)) != 1)
    _draw_format(g, 0)  # резервируем место, настоящие биты — после выбора маски


def _draw_format(g, mask):
    data = FORMAT_BITS_M << 3 | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    bits = (data << 10 | rem) ^ 0x5412
    bit = lambda i: (bits >> i) & 1 != 0  # noqa: E731
    for i in range(6):
        g.set_fn(8, i, bit(i))
    g.set_fn(8, 7, bit(6))
    g.set_fn(8, 8, bit(7))
    g.set_fn(7, 8, bit(8))
    for i in range(9, 15):
        g.set_fn(14 - i, 8, bit(i))
    for i in range(8):
        g.set_fn(g.size - 1 - i, 8, bit(i))
    for i in range(8, 15):
        g.set_fn(8, g.size - 15 + i, bit(i))
    g.set_fn(8, g.size - 8, True)  # «тёмный модуль»


def _codewords(data, ver):
    cap = _data_codewords(ver)
    bits = [0, 1, 0, 0] + [(len(data) >> i) & 1 for i in reversed(range(8))]
    for b in data:
        bits += [(b >> i) & 1 for i in reversed(range(8))]
    bits += [0] * min(4, cap * 8 - len(bits))
    bits += [0] * (-len(bits) % 8)
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(words) < cap:
        words.append(pad)
        pad ^= 0xEC ^ 0x11
    # разбивка на блоки + коды Рида — Соломона + перемежение
    nblocks, ecc = NUM_BLOCKS[ver - 1], ECC_PER_BLOCK[ver - 1]
    raw = _raw_modules(ver) // 8
    short_count = nblocks - raw % nblocks
    short_len = raw // nblocks
    div = _rs_divisor(ecc)
    blocks, k = [], 0
    for i in range(nblocks):
        dat = words[k:k + short_len - ecc + (0 if i < short_count else 1)]
        k += len(dat)
        e = _rs_remainder(dat, div)
        if i < short_count:
            dat = dat + [0]
        blocks.append(dat + e)
    out = []
    for i in range(len(blocks[0])):
        for j, blk in enumerate(blocks):
            if i != short_len - ecc or j >= short_count:
                out.append(blk[i])
    return out


def _draw_codewords(g, words):
    i, total = 0, len(words) * 8
    right = g.size - 1
    while right >= 1:
        if right == 6:
            right = 5
        for vert in range(g.size):
            for j in range(2):
                x = right - j
                upward = (right + 1) & 2 == 0
                y = g.size - 1 - vert if upward else vert
                if not g.fn[y][x] and i < total:
                    g.m[y][x] = (words[i >> 3] >> (7 - (i & 7))) & 1 != 0
                    i += 1
        right -= 2


def _apply_mask(g, mask):
    f = MASKS[mask]
    for y in range(g.size):
        for x in range(g.size):
            if not g.fn[y][x] and f(x, y):
                g.m[y][x] = not g.m[y][x]


def _penalty(m):
    size, score = len(m), 0
    lines = ["".join("1" if v else "0" for v in row) for row in m]
    lines += ["".join("1" if m[y][x] else "0" for y in range(size)) for x in range(size)]
    for line in lines:
        run = 1
        for a, b in zip(line, line[1:] + "x"):
            if a == b:
                run += 1
            else:
                if run >= 5:
                    score += run - 2
                run = 1
        score += 40 * (line.count("10111010000") + line.count("00001011101"))
    for y in range(size - 1):
        for x in range(size - 1):
            if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                score += 3
    dark = sum(map(sum, m))
    score += 10 * (abs(dark * 20 - size * size * 10) // (size * size))
    return score


def encode(text):
    """Матрица QR-кода (список строк из bool, True = чёрный) для короткого текста/ссылки."""
    data = text.encode("utf-8")
    ver = next((v for v in range(1, 7) if len(data) + 2 <= _data_codewords(v)), None)
    if ver is None:
        raise ValueError("слишком длинный текст для QR (максимум ~100 символов)")
    words = _codewords(data, ver)
    best = None
    for mask in range(8):
        g = _Grid(ver)
        _draw_function_patterns(g, ver)
        _draw_codewords(g, words)
        _apply_mask(g, mask)
        _draw_format(g, mask)
        p = _penalty(g.m)
        if best is None or p < best[0]:
            best = (p, g.m)
    return best[1]

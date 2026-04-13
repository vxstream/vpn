import subprocess, base64, datetime, re, json
from urllib.parse import unquote

INPUT_FILE  = "configs/input.txt"
OUTPUT_FILE = "runvpn.txt"
CHECK_URL   = "http://cp.cloudflare.com"   # работает из РФ
TIMEOUT     = 10

# ── Загрузка ────────────────────────────────────────────────────────────────

def load_configs(path):
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

# ── Проверка одного конфига ──────────────────────────────────────────────────

def check(cfg: str) -> tuple[bool, int]:
    try:
        r = subprocess.run(
            ["xray-knife", "http",
             "-c", cfg,
             "--url", CHECK_URL,
             "--timeout", str(TIMEOUT),
             "--tries", "1"],
            capture_output=True, text=True, timeout=TIMEOUT + 5
        )
        out = r.stdout + r.stderr
        m = re.search(r"(\d+)\s*ms", out)
        lat = int(m.group(1)) if m else 9999
        return r.returncode == 0 and lat < 8000, lat
    except Exception:
        return False, 9999

# ── Хелперы ─────────────────────────────────────────────────────────────────

def get_tag(cfg: str, i: int) -> str:
    if "#" in cfg:
        try:
            return unquote(cfg.split("#", 1)[1])[:60]
        except Exception:
            pass
    return f"node-{i}"

def strip_tag(cfg: str) -> str:
    return cfg.split("#")[0]

# ── Сборка announce (200 символов макс) ──────────────────────────────────────

def make_announce(count: int, now: str) -> str:
    text = (
        f"✅ Проверено: {now} (МСК)\n"
        f"🟢 Рабочих серверов: {count}\n"
        f"🔄 Если VPN не работает — нажми ↻ рядом с подпиской"
    )
    return base64.b64encode(text.encode("utf-8")).decode()

# ── Генерация runvpn.txt ──────────────────────────────────────────────────────

def build_subscription(working: list[tuple[str, int, str]]) -> str:
    # Время в МСК (UTC+3)
    now_utc = datetime.datetime.utcnow()
    now_msk = now_utc + datetime.timedelta(hours=3)
    now_str = now_msk.strftime("%d.%m.%Y %H:%M")

    title = "🇷🇺 RU VPN | Auto"
    title_b64 = base64.b64encode(title.encode("utf-8")).decode()

    # Сортировка: лучший пинг первым
    nodes = sorted(working, key=lambda x: x[1])

    lines = [
        # ── Стандартные заголовки Happ ──
        f"#profile-title: base64:{title_b64}",
        "#profile-update-interval: 6",
        f"#subscription-userinfo: upload=0; download=0; total=107374182400; expire=9999999999",
        "",
        # ── Анонс с датой проверки ──
        f"#announce: base64:{make_announce(len(nodes), now_str)}",
        "",
        # ── Автопинг и автоконнект к лучшему ──
        "#subscription-ping-onopen-enabled: 1",
        "#subscription-autoconnect: 1",
        "#subscription-autoconnect-type: lowestdelay",
        "",
        # ── Пинг через прокси на cloudflare (работает из РФ) ──
        "#ping-type: proxy",
        "#check-url-via-proxy: http://cp.cloudflare.com",
        "",
        # ── DNS через Яндекс для РФ доменов ──
        "#server-address-resolve-enable: 1",
        "#server-address-resolve-dns-domain: https://common.dot.dns.yandex.net/dns-query",
        "#server-address-resolve-dns-ip: 77.88.8.8",
        "",
        f"# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"# Рабочих: {len(nodes)}  |  Проверено: {now_str} МСК",
        f"# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
    ]

    for i, (cfg, lat, tag) in enumerate(nodes):
        clean = strip_tag(cfg)
        if i == 0:
            label = f"🏆 ЛУЧШИЙ | {lat}ms | {tag}"
        else:
            flag = "🇪🇺" if _is_eu(cfg) else "🌍"
            label = f"{flag} {i+1} | {lat}ms | {tag}"
        lines.append(f"{clean}#{label}")

    return "\n".join(lines) + "\n"

def _is_eu(cfg: str) -> bool:
    eu = ["de", "nl", "fi", "se", "fr", "at", "ch", "pl", "cz",
          "germany", "netherlands", "finland", "sweden",
          "frankfurt", "amsterdam", "helsinki", "paris"]
    low = cfg.lower()
    return any(k in low for k in eu)

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    configs = load_configs(INPUT_FILE)
    print(f"[*] Загружено: {len(configs)}")

    working = []
    for i, cfg in enumerate(configs):
        ok, lat = check(cfg)
        tag = get_tag(cfg, i)
        print(f"  {'✅' if ok else '❌'} [{lat}ms] {tag[:50]}")
        if ok:
            working.append((cfg, lat, tag))

    print(f"\n[*] Рабочих: {len(working)}/{len(configs)}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(build_subscription(working))

    print(f"[✓] Сохранено → {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

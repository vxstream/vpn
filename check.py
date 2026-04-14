import socket
import ssl
import re
import base64
import datetime
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE  = "configs/all_vless.txt"
OUTPUT_FILE = "runvpn.txt"
TIMEOUT     = 8
MAX_WORKERS = 50

# ── Загрузка ─────────────────────────────────────────────────────────────────

def load_configs(path):
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

# ── Парсинг URI ───────────────────────────────────────────────────────────────

def parse_cfg(cfg: str):
    """Возвращает (host, port, security, sni) из vless:// URI"""
    try:
        m = re.match(r"vless://[^@]+@([^:/?#]+):(\d+)", cfg)
        if not m:
            return None
        host, port = m.group(1), int(m.group(2))
        params_str = cfg.split("?")[1].split("#")[0] if "?" in cfg else ""
        params = dict(p.split("=", 1) for p in params_str.split("&") if "=" in p)
        security = params.get("security", "none")
        sni = params.get("sni", host)
        return host, port, security, sni
    except Exception:
        return None

# ── Проверка одного конфига ───────────────────────────────────────────────────

def check(cfg: str) -> tuple[bool, int]:
    parsed = parse_cfg(cfg)
    if not parsed:
        return False, 9999

    host, port, security, sni = parsed

    import time
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)

        if security in ("tls", "reality"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=sni)

        sock.close()
        latency = int((time.time() - start) * 1000)
        return True, latency
    except Exception:
        return False, 9999

# ── Хелперы ───────────────────────────────────────────────────────────────────

def get_tag(cfg: str, i: int) -> str:
    if "#" in cfg:
        try:
            return unquote(cfg.split("#", 1)[1])[:60]
        except Exception:
            pass
    return f"node-{i}"

def strip_tag(cfg: str) -> str:
    return cfg.split("#")[0]

def is_eu(cfg: str) -> bool:
    keywords = ["de", "nl", "fi", "se", "fr", "at", "ch", "pl", "cz",
                "germany", "netherlands", "finland", "sweden",
                "frankfurt", "amsterdam", "helsinki", "paris"]
    low = cfg.lower()
    return any(k in low for k in keywords)

# ── Анонс ─────────────────────────────────────────────────────────────────────

def make_announce(count: int, now_str: str) -> str:
    text = (
        f"✅ Проверено: {now_str} (МСК)\n"
        f"🟢 Рабочих серверов: {count}\n"
        f"🔄 Если VPN не работает — нажми ↻ у подписки"
    )
    return base64.b64encode(text.encode("utf-8")).decode()

# ── Сборка runvpn.txt ─────────────────────────────────────────────────────────

def build_subscription(working: list[tuple[str, int, str]]) -> str:
    now_msk = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
    now_str = now_msk.strftime("%d.%m.%Y %H:%M")

    title = "🇷🇺 RUN VPN"
    title_b64 = base64.b64encode(title.encode("utf-8")).decode()

    nodes = sorted(working, key=lambda x: x[1])

    lines = [
        f"#profile-title: base64:{title_b64}",
        "#profile-update-interval: 6",
        "#subscription-userinfo: upload=0; download=0; total=107374182400; expire=9999999999",
        "",
        f"#announce: base64:{make_announce(len(nodes), now_str)}",
        "",
        "#subscription-ping-onopen-enabled: 1",
        "#subscription-autoconnect: 1",
        "#subscription-autoconnect-type: lowestdelay",
        "",
        "#ping-type: proxy",
        "#check-url-via-proxy: http://cp.cloudflare.com",
        "",
        "#server-address-resolve-enable: 1",
        "#server-address-resolve-dns-domain: https://common.dot.dns.yandex.net/dns-query",
        "#server-address-resolve-dns-ip: 77.88.8.8",
        "",
        f"# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"# Рабочих: {len(nodes)}  |  Проверено: {now_str} МСК",
        f"# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
    ]

    for i, (cfg, lat, tag) in enumerate(nodes):
        clean = strip_tag(cfg)
        if i == 0:
            label = f"🏆 ЛУЧШИЙ | {lat}ms | {tag}"
        else:
            flag = "🇪🇺" if is_eu(cfg) else "🌍"
            label = f"{flag} #{i+1} | {lat}ms | {tag}"
        lines.append(f"{clean}#{label}")

    return "\n".join(lines) + "\n"

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    configs = load_configs(INPUT_FILE)
    print(f"[*] Загружено: {len(configs)}")

    working = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check, cfg): (i, cfg) for i, cfg in enumerate(configs)}
        for future in as_completed(futures):
            i, cfg = futures[future]
            ok, lat = future.result()
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

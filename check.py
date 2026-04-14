import socket
import ssl
import re
import base64
import datetime
import time
import json
import requests
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# Для DNS-запросов через Яндекс
try:
    import dns.resolver
    from dns.exception import DNSException
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[!] Библиотека dnspython не найдена. Установите: pip install dnspython")

INPUT_FILE  = "configs/all_vless.txt"
OUTPUT_FILE = "runvpn.txt"
TIMEOUT     = 8
MAX_WORKERS = 50

# Российские DNS-серверы Яндекса
DNS_SERVERS = ["77.88.8.8", "77.88.8.1"]

# ============================================================
# 1. Резолвинг DNS через Яндекс
# ============================================================
def resolve_host(host: str) -> str:
    """Возвращает IP-адрес, полученный через Яндекс.DNS."""
    if not DNS_AVAILABLE:
        return host  # fallback: резолвит сама ОС

    resolver = dns.resolver.Resolver()
    resolver.nameservers = DNS_SERVERS
    resolver.timeout = 5
    resolver.lifetime = 10

    try:
        answer = resolver.resolve(host, "A")
        return str(answer[0])
    except DNSException:
        return host  # fallback
    except Exception:
        return host

# ============================================================
# 2. Загрузка и парсинг
# ============================================================
def load_configs(path):
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def parse_cfg(cfg: str):
    """Парсит vless:// URI, возвращает словарь с параметрами."""
    try:
        m = re.match(r"vless://([^@]+)@([^:/?#]+):(\d+)", cfg)
        if not m:
            return None
        uuid_part, host, port = m.group(1), m.group(2), int(m.group(3))

        params_str = cfg.split("?")[1].split("#")[0] if "?" in cfg else ""
        params = dict(p.split("=", 1) for p in params_str.split("&") if "=" in p)

        return {
            "host": host,
            "port": port,
            "security": params.get("security", "none"),
            "sni": params.get("sni", host),
            "uuid": uuid_part,
            "flow": params.get("flow", ""),
            "type": params.get("type", "tcp"),
            "fp": params.get("fp", "chrome")
        }
    except Exception:
        return None

# ============================================================
# 3. Проверка TCP + TLS (быстрый тест)
# ============================================================
def check_tcp(parsed: dict) -> tuple[bool, int]:
    """Проверяет доступность порта с учётом TLS/Reality."""
    try:
        start = time.time()
        ip = resolve_host(parsed["host"])
        sock = socket.create_connection((ip, parsed["port"]), timeout=TIMEOUT)

        if parsed["security"] in ("tls", "reality"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=parsed["sni"])

        sock.close()
        latency = int((time.time() - start) * 1000)
        return True, latency
    except Exception:
        return False, 9999

# ============================================================
# 4. Определение страны по IP
# ============================================================
def get_country(host: str) -> tuple[str, str]:
    """Возвращает (флаг, страна) через ip-api.com."""
    try:
        ip = resolve_host(host)
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            code = data.get("countryCode", "UN")
            country = data.get("country", "Unknown")
            flag = chr(127462 + ord(code[0]) - 65) + chr(127462 + ord(code[1]) - 65)
            return flag, country
    except Exception:
        pass
    return "🌍", "Unknown"

# ============================================================
# 5. Сборка runvpn.txt
# ============================================================
def build_subscription(working: list) -> str:
    """Формирует подписку с JSON-блоком для клиентского urltest."""
    now_msk = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
    now_str = now_msk.strftime("%d.%m.%Y %H:%M")

    title_b64 = base64.b64encode("🇷🇺 RUN VPN".encode()).decode()
    announce_text = (
        f"✅ Проверено: {now_str} (МСК)\n"
        f"🟢 Рабочих серверов: {len(working)}\n"
        f"🔄 Если VPN не работает — нажми ↻ у подписки"
    )
    announce_b64 = base64.b64encode(announce_text.encode()).decode()

    lines = [
        f"#profile-title: base64:{title_b64}",
        "#profile-update-interval: 6",
        "#subscription-userinfo: upload=0; download=0; total=107374182400; expire=9999999999",
        "",
        f"#announce: base64:{announce_b64}",
        "",
        "#subscription-ping-onopen-enabled: 1",
        "#subscription-autoconnect: 1",
        "#subscription-autoconnect-type: lowestdelay",
        "",
        "#ping-type: proxy",
        "#check-url-via-proxy: http://cp.cloudflare.com",
        "",
        f"# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"# Рабочих: {len(working)}  |  Проверено: {now_str} МСК",
        f"# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
    ]

    # Строим JSON для outbounds (urltest + selector + vless)
    outbounds = [
        {
            "type": "urltest",
            "tag": "auto",
            "outbounds": [f"proxy-{i}" for i in range(len(working))],
            "url": "http://cp.cloudflare.com",
            "interval": "10m"
        },
        {
            "type": "selector",
            "tag": "proxy",
            "outbounds": ["auto"] + [f"proxy-{i}" for i in range(len(working))],
            "default": "auto"
        }
    ]

    for i, (cfg, lat) in enumerate(working):
        parsed = parse_cfg(cfg)
        flag, country = get_country(parsed["host"])
        new_tag = f"{flag} {country} #{i+1}"

        clean_cfg = cfg.split("#")[0]
        lines.append(f"{clean_cfg}#{new_tag}")

        # Добавляем vless-ноду в JSON
        outbounds.append({
            "type": "vless",
            "tag": f"proxy-{i}",
            "server": parsed["host"],
            "server_port": parsed["port"],
            "uuid": parsed["uuid"],
            "flow": parsed["flow"],
            "tls": {
                "enabled": parsed["security"] in ("tls", "reality"),
                "server_name": parsed["sni"]
            },
            "packet_encoding": "xudp"
        })

    lines.append("")
    lines.append("# ========== JSON КОНФИГУРАЦИЯ ДЛЯ АВТОВЫБОРА ==========")
    lines.append(json.dumps({"outbounds": outbounds}, indent=2, ensure_ascii=False))
    lines.append("# =======================================================")

    return "\n".join(lines) + "\n"

# ============================================================
# 6. Main
# ============================================================
def main():
    configs = load_configs(INPUT_FILE)
    print(f"[*] Загружено: {len(configs)}")

    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for cfg in configs:
            parsed = parse_cfg(cfg)
            if not parsed:
                continue
            futures[executor.submit(check_tcp, parsed)] = (cfg, parsed)

        for future in as_completed(futures):
            cfg, parsed = futures[future]
            ok, lat = future.result()
            tag = unquote(cfg.split("#")[1]) if "#" in cfg else parsed["host"]
            print(f"  {'✅' if ok else '❌'} [{lat}ms] {tag[:50]}")
            if ok:
                working.append((cfg, lat))

    working.sort(key=lambda x: x[1])
    print(f"\n[*] Рабочих: {len(working)}/{len(configs)}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(build_subscription(working))

    print(f"[✓] Сохранено → {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

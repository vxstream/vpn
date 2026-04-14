import socket
import ssl
import re
import base64
import datetime
import time
import subprocess
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

# Настройки DNS (Яндекс)
DNS_SERVERS = ["77.88.8.8", "77.88.8.1"]

# ============================================================
# 1. РЕЗОЛВИНГ DNS ЧЕРЕЗ РОССИЙСКИЕ СЕРВЕРА
# ============================================================
def resolve_host(host: str) -> str | None:
    """Резолвит хост через Яндекс.DNS, игнорируя системный DNS."""
    if not DNS_AVAILABLE:
        # fallback на системный резолвер, если dnspython нет
        try:
            return socket.gethostbyname(host)
        except:
            return None

    resolver = dns.resolver.Resolver()
    resolver.nameservers = DNS_SERVERS
    resolver.timeout = 5
    resolver.lifetime = 10

    try:
        answer = resolver.resolve(host, "A")
        return str(answer[0]) if answer else None
    except DNSException:
        return None
    except Exception:
        return None

# ============================================================
# 2. ЗАГРУЗКА И ПАРСИНГ КОНФИГОВ
# ============================================================
def load_configs(path):
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def parse_cfg(cfg: str):
    """Парсит vless:// URI, возвращает (host, port, security, sni, uuid, flow, type, fp)"""
    try:
        m = re.match(r"vless://([^@]+)@([^:/?#]+):(\d+)", cfg)
        if not m:
            return None
        uuid_part, host, port = m.group(1), m.group(2), int(m.group(3))
        
        # Парсим параметры после "?"
        params_str = cfg.split("?")[1].split("#")[0] if "?" in cfg else ""
        params = dict(p.split("=", 1) for p in params_str.split("&") if "=" in p)
        
        security = params.get("security", "none")
        sni = params.get("sni", host)
        flow = params.get("flow", "")
        type_ = params.get("type", "tcp")
        fp = params.get("fp", "chrome")
        
        return {
            "host": host,
            "port": port,
            "security": security,
            "sni": sni,
            "uuid": uuid_part,
            "flow": flow,
            "type": type_,
            "fp": fp
        }
    except Exception:
        return None

# ============================================================
# 3. ПРОВЕРКА TCP-СОЕДИНЕНИЯ (ПЕРВЫЙ СЛОЙ)
# ============================================================
def check_tcp(host: str, port: int) -> tuple[bool, int]:
    """Быстрая проверка TCP-порта перед запуском Xray."""
    try:
        start = time.time()
        ip = resolve_host(host)
        if not ip:
            return False, 9999
        sock = socket.create_connection((ip, port), timeout=TIMEOUT)
        sock.close()
        latency = int((time.time() - start) * 1000)
        return True, latency
    except Exception:
        return False, 9999

# ============================================================
# 4. ПРОВЕРКА ЧЕРЕЗ XRAY (ВТОРОЙ СЛОЙ)
# ============================================================
def test_with_xray(parsed: dict, tag: str) -> tuple[bool, int]:
    """Запускает Xray и проверяет реальную работу прокси."""
    # Генерируем уникальный порт для локального SOCKS5
    import random
    socks_port = random.randint(20000, 50000)
    
    # Строим outbound-конфиг для Xray
    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": parsed["host"],
                "port": parsed["port"],
                "users": [{
                    "id": parsed["uuid"],
                    "flow": parsed["flow"] if parsed["flow"] else "",
                    "encryption": "none",
                    "level": 0
                }]
            }]
        },
        "streamSettings": {
            "network": parsed["type"],
            "security": parsed["security"],
            "tlsSettings": {"serverName": parsed["sni"]} if parsed["security"] == "tls" else None,
            "realitySettings": {"serverName": parsed["sni"], "fingerprint": parsed["fp"]} if parsed["security"] == "reality" else None,
        },
        "tag": tag
    }
    
    # Убираем пустые настройки
    if not outbound["streamSettings"]["tlsSettings"]:
        del outbound["streamSettings"]["tlsSettings"]
    if not outbound["streamSettings"]["realitySettings"]:
        del outbound["streamSettings"]["realitySettings"]
    
    config = {
        "inbounds": [{
            "tag": "socks-in",
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True}
        }],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
    }
    
    config_path = f"/tmp/xray_{tag}.json"
    with open(config_path, "w") as f:
        json.dump(config, f)
    
    try:
        start = time.time()
        proc = subprocess.Popen(
            ["xray", "run", "-c", config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(2)  # Ждём запуск
        
        # Проверяем через SOCKS5
        import socks
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, "127.0.0.1", socks_port)
        s.settimeout(TIMEOUT)
        s.connect(("cp.cloudflare.com", 80))
        s.send(b"GET / HTTP/1.1\r\nHost: cp.cloudflare.com\r\n\r\n")
        data = s.recv(1024)
        s.close()
        
        proc.terminate()
        latency = int((time.time() - start) * 1000)
        return True, latency
    except Exception:
        return False, 9999
    finally:
        subprocess.run(["rm", "-f", config_path], check=False)

# ============================================================
# 5. ОПРЕДЕЛЕНИЕ СТРАНЫ ПО IP
# ============================================================
def get_country(host: str) -> tuple[str, str]:
    """Возвращает (код_страны, полное_название) через ip-api.com"""
    try:
        ip = resolve_host(host)
        if not ip:
            return "🌍", "Unknown"
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            code = data.get("countryCode", "UN")
            country = data.get("country", "Unknown")
            flag = chr(127462 + ord(code[0]) - 65) + chr(127462 + ord(code[1]) - 65)
            return flag, country
    except:
        pass
    return "🌍", "Unknown"

# ============================================================
# 6. СБОРКА RUNVPN.TXT
# ============================================================
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

def make_announce(count: int, now_str: str) -> str:
    text = (
        f"✅ Проверено: {now_str} (МСК)\n"
        f"🟢 Рабочих серверов: {count}\n"
        f"🔄 Если VPN не работает — нажми ↻ у подписки"
    )
    return base64.b64encode(text.encode("utf-8")).decode()

def build_subscription(working: list[tuple[str, int, str]]) -> str:
    now_msk = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
    now_str = now_msk.strftime("%d.%m.%Y %H:%M")

    title = "🇷🇺 RUN VPN"
    title_b64 = base64.b64encode(title.encode("utf-8")).decode()

    # Сортируем по задержке (Xray latency)
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
        # Определяем страну и меняем название
        parsed = parse_cfg(cfg)
        if parsed:
            flag, country = get_country(parsed["host"])
            new_tag = f"{flag} {country} #{i+1}"
        else:
            new_tag = f"🌍 Unknown #{i+1}"
        lines.append(f"{clean}#{new_tag}")

    # === ДОБАВЛЯЕМ JSON ДЛЯ АВТОВЫБОРА ===
    json_config = {
        "outbounds": [
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": [f"proxy-{i}" for i in range(len(nodes))],
                "url": "http://cp.cloudflare.com",
                "interval": "10m"
            },
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": ["auto"] + [f"proxy-{i}" for i in range(len(nodes))],
                "default": "auto"
            }
        ]
    }
    for i, (cfg, _, _) in enumerate(nodes):
        clean = strip_tag(cfg)
        json_config["outbounds"].append({
            "type": "vless",
            "tag": f"proxy-{i}",
            "server": parse_cfg(cfg)["host"],
            "server_port": parse_cfg(cfg)["port"],
            "uuid": parse_cfg(cfg)["uuid"],
            "flow": parse_cfg(cfg)["flow"],
            "tls": {"enabled": parse_cfg(cfg)["security"] in ("tls", "reality"), "server_name": parse_cfg(cfg)["sni"]},
            "packet_encoding": "xudp"
        })
    
    lines.append("")
    lines.append("# ========== JSON КОНФИГУРАЦИЯ ДЛЯ АВТОВЫБОРА ==========")
    lines.append(json.dumps(json_config, indent=2, ensure_ascii=False))
    lines.append("# =======================================================")

    return "\n".join(lines) + "\n"

# ============================================================
# 7. MAIN
# ============================================================
def main():
    configs = load_configs(INPUT_FILE)
    print(f"[*] Загружено: {len(configs)}")

    working = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for i, cfg in enumerate(configs):
            parsed = parse_cfg(cfg)
            if not parsed:
                continue
            tag = get_tag(cfg, i)
            # Шаг 1: TCP-проверка
            ok_tcp, lat_tcp = check_tcp(parsed["host"], parsed["port"])
            if not ok_tcp:
                print(f"  ❌ [TCP fail] {tag[:50]}")
                continue
            # Шаг 2: Проверка через Xray
            future = executor.submit(test_with_xray, parsed, tag)
            futures[future] = (i, cfg, parsed)
        
        for future in as_completed(futures):
            i, cfg, parsed = futures[future]
            ok_xray, lat = future.result()
            tag = get_tag(cfg, i)
            print(f"  {'✅' if ok_xray else '❌'} [{lat}ms] {tag[:50]}")
            if ok_xray:
                working.append((cfg, lat, tag))

    print(f"\n[*] Рабочих: {len(working)}/{len(configs)}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(build_subscription(working))

    print(f"[✓] Сохранено → {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

import socket
import ssl
import sys
import base64
import time
import json
import requests
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

try:
    import dns.resolver
    from dns.exception import DNSException
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

INPUT_FILE = "configs/all_vless.txt"
OUTPUT_FILE = "runvpn.txt"
TIMEOUT = 5
MAX_WORKERS = 300
COUNTRY_WORKERS = 50
CHECK_URL = "http://cp.cloudflare.com"
DNS_SERVERS = ["77.88.8.8", "77.88.8.1"]

_country_cache = {}

# Список сервисов для определения страны (без ключей)
GEO_SERVICES = [
    lambda ip: _ip_api_com(ip),
    lambda ip: _ip_api_io(ip),
    lambda ip: _ipinfo_io(ip),
]

def _ip_api_com(ip):
    """ip-api.com — основной, но иногда банит"""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode", timeout=3)
        d = r.json()
        if d.get("status") == "success" and d.get("countryCode"):
            return d["countryCode"], d["country"]
    except:
        pass
    return None, None

def _ip_api_io(ip):
    """ip-api.io — бесплатный, без лимитов"""
    try:
        r = requests.get(f"https://ip-api.io/json/{ip}", timeout=3)
        d = r.json()
        if d.get("country_code") and d.get("country"):
            return d["country_code"], d["country"]
    except:
        pass
    return None, None

def _ipinfo_io(ip):
    """ipinfo.io — бесплатный, 1000 запросов/день"""
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        d = r.json()
        if d.get("country") and len(d["country"]) == 2:
            return d["country"], d.get("city", "")
    except:
        pass
    return None, None

def resolve_host(host: str) -> str:
    if not DNS_AVAILABLE:
        return host
    resolver = dns.resolver.Resolver()
    resolver.nameservers = DNS_SERVERS
    resolver.timeout = 3
    resolver.lifetime = 5
    try:
        return str(resolver.resolve(host, "A")[0])
    except Exception:
        return host

def load_configs(path):
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def parse_vless_url(cfg: str):
    try:
        without_scheme = cfg[8:]
        if "@" not in without_scheme:
            return None
        uuid_part, rest = without_scheme.split("@", 1)
        if "?" not in rest:
            return None
        host_port, params_str = rest.split("?", 1)
        fragment = ""
        if "#" in host_port:
            host_port, fragment = host_port.split("#", 1)
        elif "#" in params_str:
            params_str, fragment = params_str.split("#", 1)
        host, port = host_port.rsplit(":", 1)
        params = {}
        for p in params_str.split("&"):
            if "=" in p:
                k, v = p.split("=", 1)
                params[k] = v
        return {
            "raw": cfg,
            "uuid": uuid_part,
            "host": host,
            "port": int(port),
            "security": params.get("security", "none"),
            "sni": params.get("sni", host),
            "flow": params.get("flow", ""),
            "type": params.get("type", "tcp"),
            "fp": params.get("fp", "chrome"),
            "pbk": params.get("pbk", ""),
            "sid": params.get("sid", ""),
            "encryption": params.get("encryption", "none"),
            "path": params.get("path", ""),
            "host_header": params.get("host", ""),
            "service_name": params.get("serviceName", ""),
            "name": unquote(fragment) if fragment else f"{host}:{port}"
        }
    except Exception:
        return None

def check_tcp_fast(parsed: dict):
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
        return True, int((time.time() - start) * 1000)
    except Exception:
        return False, 9999

def code_to_flag(code):
    """Конвертирует 2-буквенный код страны в флаг"""
    if not code or len(code) != 2:
        return "🌍"
    try:
        return chr(127462 + ord(code[0].upper()) - 65) + chr(127462 + ord(code[1].upper()) - 65)
    except:
        return "🌍"

def get_country(host: str):
    if host in _country_cache:
        return _country_cache[host]

    ip = resolve_host(host)

    # Пробуем все сервисы по очереди
    for service in GEO_SERVICES:
        code, name = service(ip)
        if code and name:
            flag = code_to_flag(code)
            result = (flag, name, code)
            _country_cache[host] = result
            return result

    result = ("🌍", "Unknown", "XX")
    _country_cache[host] = result
    return result

def build_vless_outbound(cfg: str, tag: str) -> dict:
    parsed = parse_vless_url(cfg)
    if not parsed:
        return None

    out = {
        "type": "vless",
        "tag": tag,
        "server": parsed["host"],
        "server_port": parsed["port"],
        "uuid": parsed["uuid"],
        "flow": parsed["flow"],
        "packet_encoding": "xudp",
        "tls": {
            "enabled": parsed["security"] in ("tls", "reality"),
            "server_name": parsed["sni"],
            "insecure": False,
            "utls": {"enabled": True, "fingerprint": parsed["fp"]}
        }
    }

    if parsed["security"] == "reality":
        out["tls"]["reality"] = {
            "enabled": True,
            "public_key": parsed["pbk"],
            "short_id": parsed["sid"]
        }

    if parsed["type"] == "ws":
        out["transport"] = {
            "type": "ws",
            "path": parsed["path"],
            "headers": {"Host": parsed["host_header"]} if parsed["host_header"] else {}
        }
    elif parsed["type"] == "grpc":
        out["transport"] = {"type": "grpc", "service_name": parsed["service_name"]}
    elif parsed["type"] in ("xhttp", "http"):
        out["transport"] = {
            "type": "http",
            "path": parsed["path"],
            "host": [parsed["host_header"]] if parsed["host_header"] else []
        }

    return out

def build_subscription(working_with_country: list) -> str:
    now_msk = datetime.now(timezone.utc) + timedelta(hours=3)
    now_str = now_msk.strftime("%d.%m.%Y %H:%M")
    count = len(working_with_country)

    title_b64 = base64.b64encode("🇷🇺 RUN VPN".encode()).decode()
    announce_text = f"✅ Проверено: {now_str} (МСК)\n🟢 Рабочих серверов: {count}\n🔄 Если VPN не работает — нажми ↻ у подписки"
    announce_b64 = base64.b64encode(announce_text.encode()).decode()

    # Формируем vless:// строки — формат Happ/Hiddify
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
        f"#check-url-via-proxy: {CHECK_URL}",
        "#url-test: http://cp.cloudflare.com",
        "#url-test-interval: 3m",
        "#url-test-timeout: 5s",
        "",
        f"# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"# Рабочих: {count}  |  Проверено: {now_str} МСК",
        f"# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
    ]

    for i, (cfg, lat, flag, country, code) in enumerate(working_with_country):
        tag = f"{flag} {country} #{i+1}"
        clean_cfg = cfg.split("#")[0]
        lines.append(f"{clean_cfg}#{tag}")

    return "\n".join(lines) + "\n"

def main():
    configs = load_configs(INPUT_FILE)
    print(f"[*] Загружено: {len(configs)}")

    # Этап 1: Быстрая проверка TCP
    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for cfg in configs:
            parsed = parse_vless_url(cfg)
            if not parsed:
                continue
            futures[executor.submit(check_tcp_fast, parsed)] = (cfg, parsed)

        completed = 0
        total = len(futures)
        for future in as_completed(futures):
            cfg, parsed = futures[future]
            try:
                ok, lat = future.result(timeout=TIMEOUT)
                if ok:
                    working.append((cfg, lat))
                completed += 1
                if completed % 100 == 0:
                    print(f"  Проверено: {completed}/{total}, Рабочих: {len(working)}")
            except (TimeoutError, Exception):
                completed += 1

    working.sort(key=lambda x: x[1])
    print(f"\n[+] Рабочих: {len(working)}/{len(configs)}")
    print(f"[*] Определение стран...")

    # Этап 2: Определение стран параллельно
    unique_hosts = list(set(parse_vless_url(cfg)["host"] for cfg, _ in working if parse_vless_url(cfg)))

    with ThreadPoolExecutor(max_workers=COUNTRY_WORKERS) as executor:
        futures = {executor.submit(get_country, host): host for host in unique_hosts}
        done_count = 0
        for future in as_completed(futures):
            try:
                future.result(timeout=5)
                done_count += 1
                if done_count % 50 == 0:
                    print(f"  Страны: {done_count}/{len(unique_hosts)}")
            except:
                done_count += 1

    print(f"[+] Страны определены: {len(_country_cache)}")

    # Этап 3: Сборка финального списка
    working_with_country = []
    for cfg, lat in working:
        parsed = parse_vless_url(cfg)
        if parsed:
            flag, country, code = get_country(parsed["host"])
            working_with_country.append((cfg, lat, flag, country, code))
        else:
            working_with_country.append((cfg, lat, "🌍", "Unknown", "XX"))

    print(f"[*] Генерация подписки...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(build_subscription(working_with_country))

    print(f"[✓] Сохранено → {OUTPUT_FILE}")
    sys.exit(0)

if __name__ == "__main__":
    main()

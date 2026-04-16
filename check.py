import socket
import ssl
import sys
import base64
import json
import requests
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import dns.resolver
    from dns.exception import DNSException
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

INPUT_FILE = "configs/all_vless.txt"
OUTPUT_FILE = "runvpn.txt"

# ================== ГЕОЛОКАЦИЯ (оставляем как было) ==================
_country_cache = {}

GEO_SERVICES = [
    lambda ip: _ip_api_com(ip),
    lambda ip: _ip_api_io(ip),
    lambda ip: _ipinfo_io(ip),
]

def _ip_api_com(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode", timeout=3)
        d = r.json()
        if d.get("status") == "success" and d.get("countryCode"):
            return d["countryCode"], d["country"]
    except:
        pass
    return None, None

def _ip_api_io(ip):
    try:
        r = requests.get(f"https://ip-api.io/json/{ip}", timeout=3)
        d = r.json()
        if d.get("country_code") and d.get("country"):
            return d["country_code"], d["country"]
    except:
        pass
    return None, None

def _ipinfo_io(ip):
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        d = r.json()
        if d.get("country") and len(d.get("country", "")) == 2:
            return d["country"], d.get("city", "")
    except:
        pass
    return None, None

def resolve_host(host: str) -> str:
    if not DNS_AVAILABLE:
        return host
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["77.88.8.8", "77.88.8.1"]
    resolver.timeout = 3
    resolver.lifetime = 5
    try:
        return str(resolver.resolve(host, "A")[0])
    except:
        return host

def load_configs(path):
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def parse_vless_url(cfg: str):
    # твой существующий парсер (оставил без изменений)
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
            "name": unquote(fragment) if fragment else f"{host}:{port}"
        }
    except Exception:
        return None

def code_to_flag(code):
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

def build_xray_outbound(parsed: dict, tag: str) -> dict:
    # твой существующий билдер (оставил почти без изменений)
    stream = {"network": parsed["type"]}

    if parsed["security"] == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": parsed["sni"],
            "publicKey": parsed["pbk"],
            "shortId": parsed["sid"],
            "fingerprint": parsed["fp"],
            "spiderX": "/"
        }
    elif parsed["security"] == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": parsed["sni"],
            "fingerprint": parsed["fp"]
        }
    else:
        stream["security"] = "none"

    user = {"id": parsed["uuid"], "encryption": "none"}
    if parsed["flow"]:
        user["flow"] = parsed["flow"]

    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {"vnext": [{"address": parsed["host"], "port": parsed["port"], "users": [user]}]},
        "streamSettings": stream
    }

def build_subscription(all_configs: list) -> str:
    now_msk = datetime.now(timezone.utc) + timedelta(hours=3)
    now_str = now_msk.strftime("%d.%m.%Y %H:%M")
    count = len(all_configs)

    title_b64 = base64.b64encode("LegionRKN".encode()).decode()
    announce_text = f"✅ Обновлено: {now_str} МСК\n🟢 Серверов: {count}"
    announce_b64 = base64.b64encode(announce_text.encode()).decode()

    # 1. VLESS ссылки для всех клиентов
    vless_lines = []
    for i, cfg in enumerate(all_configs):
        parsed = parse_vless_url(cfg)
        if not parsed:
            continue
        flag, country, _ = get_country(parsed["host"])
        tag = f"{flag} {country} #{i+1}"
        clean_cfg = cfg.split("#")[0]
        vless_lines.append(f"{clean_cfg}#{tag}")

    # 2. Специальный "балансер" как первая ссылка (многие клиенты его используют как URL Test)
    balancer_vless = "vless://00000000-0000-0000-0000-000000000000@balancer.runvpn.best:443?security=none&type=tcp#🇷🇺 AUTO BEST (leastPing)"

    # 3. Полный JSON с настоящим балансером (для продвинутых клиентов)
    outbounds = []
    for i, cfg in enumerate(all_configs):
        parsed = parse_vless_url(cfg)
        if not parsed: continue
        flag, country, _ = get_country(parsed["host"])
        tag = f"{flag} {country} #{i+1}"
        outbounds.append(build_xray_outbound(parsed, tag))

    full_config = {
        "log": {"loglevel": "warning"},
        "observatory": {
            "subjectSelector": [""],   # или ["🌍"] если теги начинаются с флага
            "probeUrl": "https://www.gstatic.com/generate_204",
            "probeInterval": "10s"
        },
        "outbounds": outbounds + [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}
        ],
        "balancers": [{
            "tag": "best",
            "type": "leastPing",
            "selector": [""],          # подбирает все outbound'ы
            "fallbackTag": "direct"
        }],
        "routing": {
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "balancerTag": "best"}
            ]
        }
    }

    json_str = json.dumps(full_config, ensure_ascii=False, separators=(",", ":"))

    # Собираем всё вместе
    meta_lines = [
        f"#profile-title: base64:{title_b64}",
        "#profile-update-interval: 6",
        f"#announce: base64:{announce_b64}",
        "",
        "#subscription-autoconnect: 1",
        "#subscription-autoconnect-type: lowestdelay",   # важная строка для многих клиентов
        "#url-test-interval: 3m",
        "",
        "# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"# Серверов: {count} | Обновлено: {now_str} МСК",
        "# Первый в списке — Авто Балансер",
        "# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        ""
    ]

    final_content = (
        "\n".join(meta_lines) +
        balancer_vless + "\n" +          # ← вот этот трюк
        "\n".join(vless_lines) +
        "\n\n# === FULL JSON CONFIG WITH BALANCER (для Hiddify/Nekobox) ===\n" +
        json_str + "\n"
    )

    return final_content


def main():
    configs = load_configs(INPUT_FILE)
    print(f"[*] Загружено конфигов: {len(configs)}")

    # Определяем страны для всех
    print("[*] Определяем страны...")
    unique_hosts = set()
    parsed_list = []
    for cfg in configs:
        parsed = parse_vless_url(cfg)
        if parsed:
            parsed_list.append((cfg, parsed))
            unique_hosts.add(parsed["host"])

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(get_country, host): host for host in unique_hosts}
        for future in as_completed(futures):
            future.result()  # просто прогреваем кэш

    print(f"[+] Страны определены для {len(_country_cache)} хостов")

    # Сортируем (можно по стране + latency, но latency нет)
    parsed_list.sort(key=lambda x: (get_country(x[1]["host"])[1], x[1]["host"]))

    print(f"[*] Генерация подписки с балансером...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(build_subscription([cfg for cfg, _ in parsed_list]))

    print(f"[✓] Готово → {OUTPUT_FILE}")
    print("   В подписке теперь есть:")
    print("   • Балансер 'best' (leastPing) — подключайся к нему первым")
    print("   • Все отдельные сервера ниже")
    print("   • Полный JSON-конфиг с observatory в конце")

if __name__ == "__main__":
    main()

import socket
import ssl
import sys
import base64
import json
import requests
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

try:
    import dns.resolver
    from dns.exception import DNSException
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

INPUT_FILE = "configs/all_vless.txt"
OUTPUT_FILE = "runvpn.txt"


def is_base64_encoded(data: str) -> bool:
    """Проверяет, является ли строка валидным base64."""
    if not data or len(data.strip()) == 0:
        return False

    # Убираем пробелы и переносы (на всякий случай)
    s = data.strip().replace("\n", "").replace("\r", "").replace(" ", "")

    # Быстрая проверка по символам и длине
    if not re.match(r'^[A-Za-z0-9+/=]+$', s):
        return False

    # Длина должна быть кратна 4
    if len(s) % 4 != 0:
        return False

    # Пробуем декодировать и закодировать обратно
    try:
        decoded = base64.b64decode(s, validate=True)
        reencoded = base64.b64encode(decoded).decode('ascii')
        return reencoded == s
    except Exception:
        return False


def load_configs(path):
    """Загружает конфиги. Автоматически декодирует base64, если нужно."""
    with open(path, encoding="utf-8") as f:
        content = f.read()

    # Проверяем, не является ли весь файл одной большой base64-строкой
    if is_base64_encoded(content):
        try:
            decoded_bytes = base64.b64decode(content.strip())
            decoded_text = decoded_bytes.decode('utf-8')
            print(f"[+] Обнаружена base64-подписка, успешно декодировано ({len(decoded_text)} символов)")
            lines = decoded_text.splitlines()
        except Exception as e:
            print(f"[-] Ошибка декодирования base64: {e}")
            lines = content.splitlines()
    else:
        lines = content.splitlines()

    # Фильтруем: убираем пустые и комментарии
    configs = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
    return configs


# ================== ГЕОЛОКАЦИЯ (без изменений) ==================
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

def parse_vless_url(cfg: str):
    # твой существующий парсер (без изменений)
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

# ... (остальной код без изменений: code_to_flag, get_country, build_xray_outbound, 
#      build_subscription, build_clash_config, main())

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
            future.result()  # прогреваем кэш

    print(f"[+] Страны определены для {len(_country_cache)} хостов")

    parsed_list.sort(key=lambda x: (get_country(x[1]["host"])[1], x[1]["host"]))

    print(f"[*] Генерация подписки с балансером...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(build_subscription([cfg for cfg, _ in parsed_list]))

    print("[*] Генерация Clash конфига...")
    with open("runvpn_clash.yaml", "w", encoding="utf-8") as f:
        f.write(build_clash_config([cfg for cfg, _ in parsed_list]))

    print("[✓] Готово:")
    print("   → runvpn.txt          (для v2rayN, Nekobox, Hiddify)")
    print("   → runvpn_clash.yaml   (для Clash / FlClash / Mihomo)")

if __name__ == "__main__":
    main()

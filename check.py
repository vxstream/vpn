"""
check.py — Legion VPN subscription builder
Проверяет конфиги по TCP, определяет страну через несколько API,
генерирует JSON-массив и Clash Meta конфиг.
"""

import asyncio
import base64
import json
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import yaml  # pip install pyyaml httpx

# ─── Пути ────────────────────────────────────────────────────────────────────

INPUT_FILE  = "configs/all_vless.txt"
OUTPUT_JSON = "runvpn.json"
OUTPUT_YAML = "legion_clash.yaml"
OUTPUT_LOG  = "check_log.txt"

# ─── Гео ─────────────────────────────────────────────────────────────────────

COUNTRY_FLAGS: dict[str, str] = {
    "US": "🇺🇸", "DE": "🇩🇪", "NL": "🇳🇱", "FR": "🇫🇷",
    "GB": "🇬🇧", "FI": "🇫🇮", "SE": "🇸🇪", "CH": "🇨🇭",
    "AT": "🇦🇹", "JP": "🇯🇵", "SG": "🇸🇬", "HK": "🇭🇰",
    "PL": "🇵🇱", "CZ": "🇨🇿", "UA": "🇺🇦", "TR": "🇹🇷",
    "RU": "🇷🇺", "KZ": "🇰🇿", "AE": "🇦🇪", "LT": "🇱🇹",
    "LV": "🇱🇻", "EE": "🇪🇪", "BG": "🇧🇬", "RO": "🇷🇴",
    "CA": "🇨🇦", "AU": "🇦🇺", "BR": "🇧🇷", "IN": "🇮🇳",
    "IT": "🇮🇹", "ES": "🇪🇸", "PT": "🇵🇹", "NO": "🇳🇴",
    "DK": "🇩🇰", "BE": "🇧🇪", "HU": "🇭🇺", "GR": "🇬🇷",
    "SK": "🇸🇰", "HR": "🇭🇷", "RS": "🇷🇸", "MD": "🇲🇩",
    "GE": "🇬🇪", "AM": "🇦🇲", "AZ": "🇦🇿", "UZ": "🇺🇿",
    "KR": "🇰🇷", "TW": "🇹🇼", "TH": "🇹🇭", "MY": "🇲🇾",
    "ID": "🇮🇩", "VN": "🇻🇳", "IL": "🇮🇱", "ZA": "🇿🇦",
}

COUNTRY_NAMES: dict[str, str] = {
    "US": "United States", "DE": "Germany", "NL": "Netherlands", "FR": "France",
    "GB": "United Kingdom", "FI": "Finland", "SE": "Sweden", "CH": "Switzerland",
    "AT": "Austria", "JP": "Japan", "SG": "Singapore", "HK": "Hong Kong",
    "PL": "Poland", "CZ": "Czechia", "UA": "Ukraine", "TR": "Turkey",
    "RU": "Russia", "KZ": "Kazakhstan", "AE": "UAE", "LT": "Lithuania",
    "LV": "Latvia", "EE": "Estonia", "BG": "Bulgaria", "RO": "Romania",
    "CA": "Canada", "AU": "Australia", "BR": "Brazil", "IN": "India",
    "IT": "Italy", "ES": "Spain", "PT": "Portugal", "NO": "Norway",
    "DK": "Denmark", "BE": "Belgium", "HU": "Hungary", "GR": "Greece",
    "SK": "Slovakia", "HR": "Croatia", "RS": "Serbia", "MD": "Moldova",
    "GE": "Georgia", "AM": "Armenia", "AZ": "Azerbaijan", "UZ": "Uzbekistan",
    "KR": "South Korea", "TW": "Taiwan", "TH": "Thailand", "MY": "Malaysia",
    "ID": "Indonesia", "VN": "Vietnam", "IL": "Israel", "ZA": "South Africa",
}

GEO_APIS = [
    lambda ip: f"https://ipwho.is/{ip}",
    lambda ip: f"https://ipapi.co/{ip}/json/",
    lambda ip: f"https://freeipapi.com/api/json/{ip}",
    lambda ip: f"https://ip.guide/{ip}",
    lambda ip: f"https://api.iplocation.net/?ip={ip}",
]

# ─── Датакласс результата ─────────────────────────────────────────────────────

@dataclass
class CheckResult:
    tag:     str
    name:    str
    host:    str
    port:    int
    tcp_ms:  float | None
    country: str
    flag:    str
    alive:   bool


# ─── Парсинг VLESS URL ────────────────────────────────────────────────────────

def load_configs(path: str) -> list[str]:
    return [
        l.strip() for l in Path(path).read_text(encoding="utf-8").splitlines()
        if l.strip() and not l.startswith("#")
    ]


def parse_vless_url(cfg: str) -> dict | None:
    try:
        if not cfg.startswith("vless://"):
            return None
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
        params: dict[str, str] = {}
        for p in params_str.split("&"):
            if "=" in p:
                k, v = p.split("=", 1)
                params[k] = v
        return {
            "raw":         cfg,
            "uuid":        uuid_part,
            "host":        host,
            "port":        int(port),
            "security":    params.get("security", "none"),
            "sni":         params.get("sni", host),
            "flow":        params.get("flow", ""),
            "type":        params.get("type", "tcp"),
            "fp":          params.get("fp", "chrome"),
            "pbk":         params.get("pbk", ""),
            "sid":         params.get("sid", ""),
            "path":        params.get("path", ""),
            "host_header": params.get("host", ""),
        }
    except Exception:
        return None


# ─── Построение аутбаунда Xray ───────────────────────────────────────────────

def build_xray_outbound(parsed: dict, tag: str) -> dict:
    stream: dict = {"network": parsed["type"]}

    if parsed["security"] == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName":  parsed["sni"],
            "publicKey":   parsed["pbk"],
            "shortId":     parsed["sid"],
            "fingerprint": parsed["fp"],
            "spiderX":     "/",
        }
    elif parsed["security"] == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName":  parsed["sni"],
            "fingerprint": parsed["fp"],
            "alpn":        ["h2", "http/1.1"],
        }
    else:
        stream["security"] = "none"

    if parsed["type"] == "ws":
        stream["wsSettings"] = {
            "path": parsed.get("path", "/"),
            "headers": {"Host": parsed.get("host_header") or parsed["host"]},
        }

    user: dict = {"id": parsed["uuid"], "encryption": "none", "level": 8}
    if parsed.get("flow"):
        user["flow"] = parsed["flow"]

    return {
        "tag":      tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": parsed["host"], "port": parsed["port"], "users": [user]}]
        },
        "streamSettings": stream,
    }


# ─── Описание сервера ─────────────────────────────────────────────────────────

def server_description(parsed: dict) -> str:
    """Краткое описание: протокол + транспорт + безопасность."""
    sec = parsed.get("security", "none")
    transport = parsed.get("type", "tcp")
    parts = ["VLESS"]
    if sec == "reality":
        parts.append("Reality")
    elif sec == "tls":
        parts.append("TLS")
    if transport != "tcp":
        parts.append(transport.upper())
    return " + ".join(parts)


# ─── Имя конфига ─────────────────────────────────────────────────────────────

def build_name(parsed: dict, index: int, flag: str = "🌐", country: str = "") -> str:
    country_full = COUNTRY_NAMES.get(country, "")
    num = f"#{index + 1}"
    if country_full and country != "XX":
        return f"{flag} {country_full} {num}"
    return f"{flag} Server {num}"


# ─── TCP-проверка ─────────────────────────────────────────────────────────────

def tcp_check(host: str, port: int, timeout: float = 4.0) -> float | None:
    try:
        t = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.monotonic() - t) * 1000, 1)
    except Exception:
        return None


# ─── Определение страны ───────────────────────────────────────────────────────

async def get_country(ip: str, client: httpx.AsyncClient) -> tuple[str, str]:
    for api_fn in GEO_APIS:
        try:
            r = await client.get(api_fn(ip), timeout=5.0, follow_redirects=True)
            if r.status_code != 200:
                continue
            data = r.json()
            code = (
                data.get("country_code") or
                data.get("countryCode") or
                data.get("country") or
                (data.get("location") or {}).get("country_code") or
                (data.get("network") or {}).get("country_code")
            )
            if code and isinstance(code, str) and len(code) == 2:
                code = code.upper()
                return code, COUNTRY_FLAGS.get(code, "🌐")
        except Exception:
            continue
    return "XX", "🌐"


# ─── Асинхронная проверка одного конфига ─────────────────────────────────────

async def check_one(
    parsed: dict,
    tag: str,
    index: int,
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
) -> CheckResult:
    async with sem:
        loop = asyncio.get_event_loop()
        tcp_ms = await loop.run_in_executor(None, tcp_check, parsed["host"], parsed["port"])
        alive  = tcp_ms is not None

        if alive:
            country, flag = await get_country(parsed["host"], client)
        else:
            country, flag = "XX", "🌐"

        name = build_name(parsed, index, flag, country)
        return CheckResult(
            tag=tag, name=name,
            host=parsed["host"], port=parsed["port"],
            tcp_ms=tcp_ms, country=country, flag=flag, alive=alive,
        )


# ─── Скелет Xray-конфига ──────────────────────────────────────────────────────

def xray_skeleton(remarks: str, description: str = "") -> dict:
    cfg: dict = {
        "remarks": remarks,
    }
    if description:
        cfg["serverDescription"] = description
    cfg.update({
        "log": {"loglevel": "warning", "dnsLog": False},
        "dns": {"queryStrategy": "UseIPv4", "servers": ["1.1.1.1", "1.0.0.1"]},
        "policy": {
            "levels": {
                "8": {
                    "bufferSize":    3,
                    "connIdle":      300,
                    "downlinkOnly":  4,
                    "handshake":     3,
                    "uplinkOnly":    2,
                }
            }
        },
        "inbounds": [
            {
                "tag":      "socks-in",
                "listen":   "127.0.0.1",
                "port":     10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "enabled":       True,
                    "destOverride":  ["tls", "http", "quic"],
                    "routeOnly":     True,
                    "metadataOnly":  False,
                },
            },
            {
                "tag":      "http",
                "listen":   "127.0.0.1",
                "port":     10809,
                "protocol": "http",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "enabled":       True,
                    "destOverride":  ["tls", "http", "quic"],
                    "routeOnly":     True,
                    "metadataOnly":  False,
                },
            },
        ],
    })
    return cfg


BURST_OBSERVATORY = {
    "pingConfig": {
        "connectivity": "http://connectivitycheck.platform.hicloud.com/generate_204",
        "destination":  "http://www.google.com/generate_204",
        "httpMethod":   "HEAD",
        "interval":     "5m",
        "sampling":     1,
        "timeout":      "10s",
    },
    "subjectSelector": ["proxy-"],
}


def routing_balancer(balancer_tag: str = "proxy-balancer") -> dict:
    return {
        "domainMatcher": "hybrid",
        "domainStrategy": "IPIfNonMatch",
        "balancers": [
            {
                "tag":      balancer_tag,
                "selector": ["proxy-"],
                "strategy": {"type": "leastPing"},
            }
        ],
        "rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            {"type": "field", "network": "tcp,udp",    "balancerTag": balancer_tag},
        ],
    }


def routing_single() -> dict:
    return {
        "domainMatcher": "hybrid",
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
            {"type": "field", "network": "tcp,udp",    "outboundTag": "proxy"},
        ],
    }


DIRECT_OUTBOUNDS = [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block",  "protocol": "blackhole"},
]


# ─── Описание для auto-конфигов ───────────────────────────────────────────────

def auto_description(entries: list[tuple[dict, str, CheckResult]]) -> str:
    """Собирает описание: какие типы серверов внутри группы."""
    types = set()
    for parsed, _, _ in entries:
        types.add(server_description(parsed))
    return "Auto select | " + ", ".join(sorted(types))


# ─── Сборка AUTO-конфига ──────────────────────────────────────────────────────

def build_auto_config(
    remarks: str,
    entries: list[tuple[dict, str, CheckResult]],
    description: str = "",
) -> dict:
    cfg = xray_skeleton(remarks, description)
    cfg["burstObservatory"] = BURST_OBSERVATORY
    cfg["outbounds"] = (
        [build_xray_outbound(p, t) for p, t, _ in entries]
        + DIRECT_OUTBOUNDS
    )
    cfg["routing"] = routing_balancer()
    return cfg


# ─── Сборка одиночного конфига ────────────────────────────────────────────────

def build_single_config(parsed: dict, result: CheckResult) -> dict:
    desc = server_description(parsed)
    cfg = xray_skeleton(result.name, desc)
    cfg["outbounds"] = [
        build_xray_outbound(parsed, "proxy"),
        *DIRECT_OUTBOUNDS,
    ]
    cfg["routing"] = routing_single()
    return cfg


# ─── Clash Meta конфиг ────────────────────────────────────────────────────────

def build_clash_config(entries: list[tuple[dict, str, CheckResult]]) -> str:
    proxies   = []
    names_all = []

    for parsed, tag, result in entries:
        name = result.name
        proxy: dict = {
            "name":   name,
            "type":   "vless",
            "server": parsed["host"],
            "port":   parsed["port"],
            "uuid":   parsed["uuid"],
            "udp":    True,
            "skip-cert-verify": False,
        }

        if parsed["type"] == "ws":
            proxy["network"] = "ws"
            proxy["ws-opts"] = {
                "path":    parsed.get("path", "/"),
                "headers": {"Host": parsed.get("host_header") or parsed["host"]},
            }
        else:
            proxy["network"] = "tcp"

        if parsed["security"] == "reality":
            proxy["tls"]                = True
            proxy["servername"]         = parsed["sni"] or parsed["host"]
            proxy["client-fingerprint"] = parsed.get("fp", "chrome")
            proxy["reality-opts"]       = {
                "public-key": parsed["pbk"],
                "short-id":   parsed.get("sid", ""),
            }
        elif parsed["security"] == "tls":
            proxy["tls"]                = True
            proxy["servername"]         = parsed["sni"] or parsed["host"]
            proxy["client-fingerprint"] = parsed.get("fp", "chrome")
        else:
            proxy["tls"] = False

        if parsed.get("flow"):
            proxy["flow"] = parsed["flow"]

        proxies.append(proxy)
        names_all.append(name)

    by_country: dict[str, list[str]] = {}
    for _, _, result in entries:
        if result.country != "XX":
            by_country.setdefault(result.country, []).append(result.name)

    country_groups = []
    for code, names in by_country.items():
        if len(names) >= 2:
            flag = COUNTRY_FLAGS.get(code, "🌐")
            country_groups.append({
                "name":      f"{flag} Smart {code}",
                "type":      "url-test",
                "proxies":   names,
                "url":       "https://www.gstatic.com/generate_204",
                "interval":  180,
                "tolerance": 30,
                "lazy":      True,
            })

    auto_group = {
        "name":      "🇪🇺 Smart Auto",
        "type":      "url-test",
        "proxies":   names_all,
        "url":       "https://www.gstatic.com/generate_204",
        "interval":  180,
        "tolerance": 30,
        "lazy":      True,
    }

    select_proxies = ["🇪🇺 Smart Auto"] + [g["name"] for g in country_groups] + names_all
    select_group = {
        "name":    "Select",
        "type":    "select",
        "proxies": select_proxies,
    }

    clash_cfg = {
        "mixed-port":  7890,
        "allow-lan":   False,
        "mode":        "rule",
        "log-level":   "info",
        "ipv6":        False,
        "proxies":     proxies,
        "proxy-groups": [auto_group, select_group] + country_groups,
        "rules": [
            "GEOIP,CN,DIRECT",
            "GEOIP,PRIVATE,DIRECT",
            "MATCH,Select",
        ],
    }

    return yaml.dump(clash_cfg, allow_unicode=True, sort_keys=False, default_flow_style=False)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

async def main() -> None:
    # 1. Загрузка
    raw_configs = load_configs(INPUT_FILE)
    print(f"[*] Loaded: {len(raw_configs)}")

    parsed_list: list[tuple[str, dict]] = []
    for cfg in raw_configs:
        p = parse_vless_url(cfg)
        if p:
            parsed_list.append((cfg, p))

    print(f"[*] Parsed: {len(parsed_list)}")

    # 2. Асинхронная проверка
    sem = asyncio.Semaphore(20)
    print(f"[*] Checking...")

    async with httpx.AsyncClient(
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=10.0,
    ) as client:
        tasks = [
            check_one(parsed, f"proxy-{i + 1}", i, client, sem)
            for i, (_, parsed) in enumerate(parsed_list)
        ]
        results: list[CheckResult] = await asyncio.gather(*tasks)

    # 3. Сортировка
    alive  = [(parsed_list[i][1], r) for i, r in enumerate(results) if r.alive]
    dead   = [(parsed_list[i][1], r) for i, r in enumerate(results) if not r.alive]
    alive.sort(key=lambda x: x[1].tcp_ms or 9999)

    print(f"[+] Alive: {len(alive)} | Dead: {len(dead)}")

    # 4. Лог
    log_lines = [
        f"Alive: {len(alive)} | Dead: {len(dead)}",
        "─" * 50,
    ]
    for parsed, r in alive:
        log_lines.append(f"  + {r.flag} {r.country:2}  {r.tcp_ms:>6.1f}ms  {r.host}:{r.port}")
    log_lines.append("─" * 50)
    for parsed, r in dead:
        log_lines.append(f"  - XX  TIMEOUT  {r.host}:{r.port}")
    Path(OUTPUT_LOG).write_text("\n".join(log_lines), encoding="utf-8")
    print("\n".join(log_lines[:15]))

    if not alive:
        print("[!] No alive configs.")
        return

    # 5. Переиндексация
    entries: list[tuple[dict, str, CheckResult]] = []
    for i, (parsed, result) in enumerate(alive):
        new_tag = f"proxy-{i + 1}"
        result.name = build_name(parsed, i, result.flag, result.country)
        entries.append((parsed, new_tag, result))

    # 6. Группировка по странам
    by_country: dict[str, list[tuple[dict, str, CheckResult]]] = {}
    for item in entries:
        code = item[2].country
        if code != "XX":
            by_country.setdefault(code, []).append(item)

    country_auto_configs: list[dict] = []
    for code, items in sorted(by_country.items(), key=lambda x: -len(x[1])):
        if len(items) < 2:
            continue
        flag = COUNTRY_FLAGS.get(code, "🌐")
        remarks = f"{flag} Smart {code}"
        desc = auto_description(items)
        country_auto_configs.append(build_auto_config(remarks, items, desc))
        print(f"   {flag} Smart {code}: {len(items)}")

    # 7. Главный AUTO
    auto_all = build_auto_config(
        f"🇪🇺 Smart Auto",
        entries,
        auto_description(entries),
    )

    # 8. Одиночные
    single_configs = [build_single_config(p, r) for p, _, r in entries]

    # 9. JSON
    subscription = [auto_all] + country_auto_configs + single_configs
    Path(OUTPUT_JSON).write_text(
        json.dumps(subscription, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n[+] {OUTPUT_JSON} — {len(subscription)} configs")

    # 10. Clash
    Path(OUTPUT_YAML).write_text(
        build_clash_config(entries),
        encoding="utf-8",
    )
    print(f"[+] {OUTPUT_YAML}")


if __name__ == "__main__":
    asyncio.run(main())

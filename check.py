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

# ─── Бренд ───────────────────────────────────────────────────────────────────

BRAND             = "LEGION"
ICON_UNKNOWN      = "🇸🇴"                          # звёздочка для неизвестных стран
BRAND_AUTO        = f"{ICON_UNKNOWN} {BRAND} · Авто"  # главный авто
BRAND_AUTO_PREFIX = f"{BRAND} · Авто · "            # префикс страновых авто-групп
BRAND_PREFIX      = f"{BRAND} · "                   # для будущих групп

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
    "MX": "🇲🇽", "AR": "🇦🇷", "CL": "🇨🇱", "CO": "🇨🇴",
    "IS": "🇮🇸", "LU": "🇱🇺", "CY": "🇨🇾", "MT": "🇲🇹",
}

# Русские названия стран
COUNTRY_NAMES_RU: dict[str, str] = {
    "US": "США",          "DE": "Германия",     "NL": "Нидерланды",   "FR": "Франция",
    "GB": "Великобритания","FI": "Финляндия",    "SE": "Швеция",       "CH": "Швейцария",
    "AT": "Австрия",      "JP": "Япония",        "SG": "Сингапур",     "HK": "Гонконг",
    "PL": "Польша",       "CZ": "Чехия",         "UA": "Украина",      "TR": "Турция",
    "RU": "Россия",       "KZ": "Казахстан",     "AE": "ОАЭ",          "LT": "Литва",
    "LV": "Латвия",       "EE": "Эстония",       "BG": "Болгария",     "RO": "Румыния",
    "CA": "Канада",       "AU": "Австралия",      "BR": "Бразилия",     "IN": "Индия",
    "IT": "Италия",       "ES": "Испания",        "PT": "Португалия",   "NO": "Норвегия",
    "DK": "Дания",        "BE": "Бельгия",        "HU": "Венгрия",      "GR": "Греция",
    "SK": "Словакия",     "HR": "Хорватия",       "RS": "Сербия",       "MD": "Молдова",
    "GE": "Грузия",       "AM": "Армения",        "AZ": "Азербайджан",  "UZ": "Узбекистан",
    "KR": "Корея",        "TW": "Тайвань",        "TH": "Таиланд",      "MY": "Малайзия",
    "ID": "Индонезия",    "VN": "Вьетнам",        "IL": "Израиль",      "ZA": "ЮАР",
    "MX": "Мексика",      "AR": "Аргентина",      "CL": "Чили",         "CO": "Колумбия",
    "IS": "Исландия",     "LU": "Люксембург",     "CY": "Кипр",         "MT": "Мальта",
}

# Английские названия (для Clash совместимости)
COUNTRY_NAMES_EN: dict[str, str] = {
    "US": "United States", "DE": "Germany",     "NL": "Netherlands",  "FR": "France",
    "GB": "United Kingdom","FI": "Finland",     "SE": "Sweden",       "CH": "Switzerland",
    "AT": "Austria",       "JP": "Japan",       "SG": "Singapore",    "HK": "Hong Kong",
    "PL": "Poland",        "CZ": "Czechia",     "UA": "Ukraine",      "TR": "Turkey",
    "RU": "Russia",        "KZ": "Kazakhstan",  "AE": "UAE",          "LT": "Lithuania",
    "LV": "Latvia",        "EE": "Estonia",     "BG": "Bulgaria",     "RO": "Romania",
    "CA": "Canada",        "AU": "Australia",   "BR": "Brazil",       "IN": "India",
    "IT": "Italy",         "ES": "Spain",       "PT": "Portugal",     "NO": "Norway",
    "DK": "Denmark",       "BE": "Belgium",     "HU": "Hungary",      "GR": "Greece",
    "SK": "Slovakia",      "HR": "Croatia",     "RS": "Serbia",       "MD": "Moldova",
    "GE": "Georgia",       "AM": "Armenia",     "AZ": "Azerbaijan",   "UZ": "Uzbekistan",
    "KR": "South Korea",   "TW": "Taiwan",      "TH": "Thailand",     "MY": "Malaysia",
    "ID": "Indonesia",     "VN": "Vietnam",     "IL": "Israel",       "ZA": "South Africa",
    "MX": "Mexico",        "AR": "Argentina",   "CL": "Chile",        "CO": "Colombia",
    "IS": "Iceland",       "LU": "Luxembourg",  "CY": "Cyprus",       "MT": "Malta",
}

GEO_APIS: list[tuple[str, callable]] = [
    # url_fn,  extractor_fn(data) → str | None
    (
        lambda ip: f"https://ipwho.is/{ip}",
        lambda d: d.get("country_code"),
    ),
    (
        lambda ip: f"https://ipapi.co/{ip}/json/",
        lambda d: d.get("country_code"),
    ),
    (
        lambda ip: f"https://freeipapi.com/api/json/{ip}",
        lambda d: d.get("countryCode"),
    ),
    (
        lambda ip: f"https://ip-api.com/json/{ip}?fields=countryCode",
        lambda d: d.get("countryCode"),
    ),
    (
        lambda ip: f"https://ipinfo.io/{ip}/json",
        lambda d: d.get("country"),
    ),
    (
        lambda ip: f"https://api.iplocation.net/?ip={ip}",
        lambda d: d.get("country_code2"),
    ),
    (
        lambda ip: f"https://ip.guide/{ip}",
        lambda d: (
            (d.get("location") or {}).get("country_code")
            or (d.get("network") or {}).get("country_code")
        ),
    ),
    (
        lambda ip: f"https://extreme-ip-lookup.com/json/{ip}?key=free",
        lambda d: d.get("countryCode"),
    ),
    (
        lambda ip: f"https://ipapi.is/json/?ip={ip}",
        lambda d: (d.get("location") or {}).get("country_code"),
    ),
    (
        lambda ip: f"https://api.ipbase.com/v1/json/?ip={ip}",
        lambda d: d.get("country_code"),
    ),
]

# ─── Датакласс результата ─────────────────────────────────────────────────────

@dataclass
class CheckResult:
    tag:          str
    name:         str
    host:         str
    port:         int
    tcp_ms:       float | None
    # entry = страна IP-адреса хоста (куда подключаемся)
    country:      str
    flag:         str
    # exit = страна куда идёт трафик (SNI hostname → resolve → geo)
    exit_country: str
    exit_flag:    str
    alive:        bool


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


# ─── Имена конфигов ───────────────────────────────────────────────────────────

def country_name_ru(code: str) -> str:
    """Русское название страны или код, если нет перевода."""
    return COUNTRY_NAMES_RU.get(code, code)


def build_name(
    parsed: dict,
    index: int,
    entry_flag: str = ICON_UNKNOWN,
    entry_code: str = "",
    exit_code:  str = "",
    exit_flag:  str = ICON_UNKNOWN,
) -> str:
    """
    Страна известна, exit совпадает или неизвестен: «🇩🇪 Германия #1»
    Entry ≠ exit (трафик уходит в другую страну): «🇷🇺→🇩🇪 Германия #1»
    Страна совсем неизвестна: «🇸🇴 Сервер #1»
    """
    num = f"#{index + 1}"

    has_entry = entry_code and entry_code != "XX"
    has_exit  = exit_code  and exit_code  != "XX"

    if has_exit and has_entry and exit_code != entry_code:
        # Трафик идёт в другую страну — показываем маршрут entry→exit
        ru_exit = country_name_ru(exit_code)
        return f"{entry_flag}→{exit_flag} {ru_exit} {num}"

    if has_exit:
        return f"{exit_flag} {country_name_ru(exit_code)} {num}"

    if has_entry:
        return f"{entry_flag} {country_name_ru(entry_code)} {num}"

    return f"{ICON_UNKNOWN} Сервер {num}"


def build_group_name(code: str, group_index: int | None = None) -> str:
    """
    Страновой авто-пул: «🇳🇱 LEGION · Авто · Нидерланды»
    С индексом: «🇳🇱 LEGION · Авто · Нидерланды 2»
    """
    flag = COUNTRY_FLAGS.get(code, ICON_UNKNOWN)
    ru   = country_name_ru(code)
    base = f"{flag} {BRAND_AUTO_PREFIX}{ru}"
    return base if group_index is None else f"{base} {group_index}"


# ─── TCP-проверка ─────────────────────────────────────────────────────────────

def tcp_check(host: str, port: int, timeout: float = 4.0) -> float | None:
    try:
        t = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout):
            return round((time.monotonic() - t) * 1000, 1)
    except Exception:
        return None


# ─── Определение страны — консенсус из всех API параллельно ─────────────────

def _extract_code(data: dict, extractor) -> str | None:
    try:
        code = extractor(data)
        if code and isinstance(code, str) and len(code) == 2:
            return code.upper()
    except Exception:
        pass
    return None


async def _query_one_geo(
    ip: str,
    url_fn,
    extractor,
    client: httpx.AsyncClient,
) -> str | None:
    try:
        url = url_fn(ip)
        r = await client.get(url, timeout=5.0, follow_redirects=True)
        if r.status_code != 200:
            return None
        data = r.json()
        return _extract_code(data, extractor)
    except Exception:
        return None


async def get_country_consensus(ip: str, client: httpx.AsyncClient) -> tuple[str, str]:
    """
    Запрашивает все GEO_APIS параллельно, голосует за наиболее популярный ответ.
    Возвращает (country_code, flag).
    """
    tasks = [_query_one_geo(ip, url_fn, ext, client) for url_fn, ext in GEO_APIS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    votes: dict[str, int] = {}
    for r in results:
        if isinstance(r, str) and r and r != "XX":
            votes[r] = votes.get(r, 0) + 1

    if not votes:
        return "XX", ICON_UNKNOWN

    winner = max(votes, key=votes.__getitem__)
    return winner, COUNTRY_FLAGS.get(winner, ICON_UNKNOWN)


async def resolve_ip(hostname: str) -> str | None:
    """DNS-резолв hostname → первый IPv4. None если не удалось."""
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return None


# ─── Асинхронная проверка одного конфига ─────────────────────────────────────

# ─── Асинхронная проверка одного конфига ─────────────────────────────────────

async def _resolve_exit_country(
    sni: str,
    fallback_host: str,
    client: httpx.AsyncClient,
) -> tuple[str, str]:
    """
    Страна выхода трафика через SNI hostname.
    Если SNI == хост или не резолвится — возвращает ("XX", ICON_UNKNOWN).
    """
    if not sni or sni == fallback_host:
        return "XX", ICON_UNKNOWN
    exit_ip = await resolve_ip(sni)
    if not exit_ip or exit_ip == fallback_host:
        return "XX", ICON_UNKNOWN
    return await get_country_consensus(exit_ip, client)


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

        if not alive:
            return CheckResult(
                tag=tag, name=f"{ICON_UNKNOWN} Сервер #{index + 1}",
                host=parsed["host"], port=parsed["port"],
                tcp_ms=None,
                country="XX",      flag=ICON_UNKNOWN,
                exit_country="XX", exit_flag=ICON_UNKNOWN,
                alive=False,
            )

        # entry и exit — параллельно
        sni = parsed.get("sni", "")
        (entry_code, entry_flag), (exit_code, exit_flag) = await asyncio.gather(
            get_country_consensus(parsed["host"], client),
            _resolve_exit_country(sni, parsed["host"], client),
        )

        name = build_name(parsed, index, entry_flag, entry_code, exit_code, exit_flag)
        return CheckResult(
            tag=tag, name=name,
            host=parsed["host"], port=parsed["port"],
            tcp_ms=tcp_ms,
            country=entry_code,    flag=entry_flag,
            exit_country=exit_code, exit_flag=exit_flag,
            alive=True,
        )


# ─── Скелет Xray-конфига ──────────────────────────────────────────────────────

def xray_skeleton(remarks: str, description: str = "") -> dict:
    cfg: dict = {"remarks": remarks}
    if description:
        cfg["meta"] = {"serverDescription": description}
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
                    "enabled":      True,
                    "destOverride": ["tls", "http", "quic"],
                    "routeOnly":    True,
                    "metadataOnly": False,
                },
            },
            {
                "tag":      "http",
                "listen":   "127.0.0.1",
                "port":     10809,
                "protocol": "http",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "enabled":      True,
                    "destOverride": ["tls", "http", "quic"],
                    "routeOnly":    True,
                    "metadataOnly": False,
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


def auto_description(entries: list[tuple[dict, str, CheckResult]]) -> str:
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
            group_name = build_group_name(code)
            country_groups.append({
                "name":      group_name,
                "type":      "url-test",
                "proxies":   names,
                "url":       "https://www.gstatic.com/generate_204",
                "interval":  180,
                "tolerance": 30,
                "lazy":      True,
            })

    auto_group = {
        "name":      BRAND_AUTO,
        "type":      "url-test",
        "proxies":   names_all,
        "url":       "https://www.gstatic.com/generate_204",
        "interval":  180,
        "tolerance": 30,
        "lazy":      True,
    }

    select_proxies = [BRAND_AUTO] + [g["name"] for g in country_groups] + names_all
    select_group = {
        "name":    f"⚡ {BRAND} · Выбор",
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
            f"MATCH,⚡ {BRAND} · Выбор",
        ],
    }

    return yaml.dump(clash_cfg, allow_unicode=True, sort_keys=False, default_flow_style=False)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

async def main() -> None:
    # 1. Загрузка
    raw_configs = load_configs(INPUT_FILE)
    print(f"[*] Загружено: {len(raw_configs)}")

    parsed_list: list[tuple[str, dict]] = []
    for cfg in raw_configs:
        p = parse_vless_url(cfg)
        if p:
            parsed_list.append((cfg, p))

    print(f"[*] Распарсено: {len(parsed_list)}")

    # 2. Асинхронная проверка
    sem = asyncio.Semaphore(20)
    print(f"[*] Проверка...")

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
    alive = [(parsed_list[i][1], r) for i, r in enumerate(results) if r.alive]
    dead  = [(parsed_list[i][1], r) for i, r in enumerate(results) if not r.alive]
    alive.sort(key=lambda x: x[1].tcp_ms or 9999)

    print(f"[+] Живых: {len(alive)} | Мёртвых: {len(dead)}")

    # 4. Лог
    log_lines = [
        f"{'─' * 60}",
        f"  {BRAND} VPN · Лог проверки",
        f"  Живых: {len(alive)}   Мёртвых: {len(dead)}",
        f"{'─' * 60}",
    ]
    for parsed, r in alive:
        ms_str = f"{r.tcp_ms:>6.1f}мс"
        if r.exit_country and r.exit_country != "XX" and r.exit_country != r.country:
            geo = (
                f"{r.flag}{country_name_ru(r.country):<12}"
                f" → {r.exit_flag}{country_name_ru(r.exit_country)}"
            )
        elif r.exit_country and r.exit_country != "XX":
            geo = f"{r.exit_flag} {country_name_ru(r.exit_country):<16}"
        elif r.country != "XX":
            geo = f"{r.flag} {country_name_ru(r.country):<16}"
        else:
            geo = f"{ICON_UNKNOWN} Неизвестно       "
        log_lines.append(f"  ✓  {geo}  {ms_str}  {r.host}:{r.port}")
    log_lines.append(f"{'─' * 60}")
    for parsed, r in dead:
        log_lines.append(f"  ✗  🇸🇴 Недоступен               TIMEOUT  {r.host}:{r.port}")
    Path(OUTPUT_LOG).write_text("\n".join(log_lines), encoding="utf-8")
    print("\n".join(log_lines[:20]))

    if not alive:
        print("[!] Нет доступных конфигов.")
        return

    # 5. Переиндексация — нумерация внутри каждой страны
    # Для имени и группировки используем exit_country (где выходит трафик),
    # при отсутствии — entry_country (IP хоста).
    country_counter: dict[str, int] = {}
    entries: list[tuple[dict, str, CheckResult]] = []
    global_index = 0

    for parsed, result in alive:
        new_tag    = f"proxy-{global_index + 1}"
        # "главная" страна для группировки — exit если есть, иначе entry
        group_code = (
            result.exit_country
            if result.exit_country and result.exit_country != "XX"
            else result.country
        )
        country_counter[group_code] = country_counter.get(group_code, 0) + 1
        idx_in_country = country_counter[group_code]

        # Пересобираем имя с точным индексом внутри страны
        if result.exit_country and result.exit_country != "XX":
            if result.exit_country != result.country and result.country != "XX":
                # entry→exit маршрут
                result.name = (
                    f"{result.flag}→{result.exit_flag} "
                    f"{country_name_ru(result.exit_country)} #{idx_in_country}"
                )
            else:
                result.name = (
                    f"{result.exit_flag} "
                    f"{country_name_ru(result.exit_country)} #{idx_in_country}"
                )
        elif result.country and result.country != "XX":
            result.name = (
                f"{result.flag} "
                f"{country_name_ru(result.country)} #{idx_in_country}"
            )
        else:
            result.name = f"{ICON_UNKNOWN} Сервер #{global_index + 1}"

        entries.append((parsed, new_tag, result))
        global_index += 1

    # 6. Группировка по exit-стране (где выходит трафик)
    by_country: dict[str, list[tuple[dict, str, CheckResult]]] = {}
    for item in entries:
        r    = item[2]
        code = r.exit_country if r.exit_country != "XX" else r.country
        if code != "XX":
            by_country.setdefault(code, []).append(item)

    # Разбивка на группы по ~10 серверов на группу
    GROUP_SIZE = 10
    country_auto_configs: list[dict] = []

    for code, items in sorted(by_country.items(), key=lambda x: -len(x[1])):
        if len(items) < 2:
            continue

        chunks = [items[i:i + GROUP_SIZE] for i in range(0, len(items), GROUP_SIZE)]
        for idx, chunk in enumerate(chunks, start=1):
            group_label = build_group_name(code, idx if len(chunks) > 1 else None)
            desc = auto_description(chunk)
            country_auto_configs.append(build_auto_config(group_label, chunk, desc))

        flag = COUNTRY_FLAGS.get(code, ICON_UNKNOWN)
        ru   = country_name_ru(code)
        print(f"   {flag} {ru}: {len(items)} серверов → {len(chunks)} групп(ы)")

    # 7. Главный AUTO
    auto_all = build_auto_config(
        BRAND_AUTO,
        entries,
        auto_description(entries),
    )

    # 8. Одиночные
    single_configs = [build_single_config(p, r) for p, _, r in entries]

    # 9. JSON — порядок: Авто → страновые группы → одиночные
    subscription = [auto_all] + country_auto_configs + single_configs
    Path(OUTPUT_JSON).write_text(
        json.dumps(subscription, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"\n[+] {OUTPUT_JSON} — {len(subscription)} конфигов")

    # 10. Clash
    Path(OUTPUT_YAML).write_text(
        build_clash_config(entries),
        encoding="utf-8",
    )
    print(f"[+] {OUTPUT_YAML} — Clash Meta конфиг")


if __name__ == "__main__":
    asyncio.run(main())

import base64
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

INPUT_FILE = "configs/all_vless.txt"
OUTPUT_FILE = "runvpn.txt"   # можешь переименовать файл позже, если хочешь


def build_beautiful_name(parsed: dict, index: int) -> str:
    """Чистое и премиальное название без гео и старого бренда"""
    sec_type = "Reality" if parsed.get("security") == "reality" else \
               "TLS" if parsed.get("security") == "tls" else "Direct"
    
    number = str(index + 1).zfill(2)
    
    # Красивое название для Legion
    return f"LEGION-{number} • {sec_type}"


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
            "path": params.get("path", ""),
            "host_header": params.get("host", ""),
        }
    except Exception:
        return None


def build_xray_outbound(parsed: dict, tag: str) -> dict:
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
    if parsed.get("flow"):
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

    title_b64 = base64.b64encode("Legion VPN".encode()).decode()
    announce_text = f"✅ Обновлено: {now_str} МСК\n🟢 Серверов: {count}\n🌐 Reality + Auto Balancer"
    announce_b64 = base64.b64encode(announce_text.encode()).decode()

    vless_lines = []
    for i, cfg in enumerate(all_configs):
        parsed = parse_vless_url(cfg)
        if not parsed:
            continue
        name = build_beautiful_name(parsed, i)
        clean_cfg = cfg.split("#")[0] if "#" in cfg else cfg
        vless_lines.append(f"{clean_cfg}#{name}")

    balancer_vless = "vless://00000000-0000-0000-0000-000000000000@balancer.legion.best:443?security=none&type=tcp#AUTO BEST (leastPing)"

    # JSON с балансером
    outbounds = []
    for i, cfg in enumerate(all_configs):
        parsed = parse_vless_url(cfg)
        if not parsed:
            continue
        name = build_beautiful_name(parsed, i)
        outbounds.append(build_xray_outbound(parsed, name))

    full_config = {
        "log": {"loglevel": "warning"},
        "observatory": {
            "subjectSelector": [""],
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
            "selector": [""],
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

    meta_lines = [
        f"#profile-title: base64:{title_b64}",
        "#profile-update-interval: 6",
        f"#announce: base64:{announce_b64}",
        "",
        "#subscription-autoconnect: 1",
        "#subscription-autoconnect-type: lowestdelay",
        "#url-test-interval: 3m",
        "",
        "# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"# LEGION • {count} серверов | {now_str} МСК",
        "# Чистые названия • локация определяется клиентом",
        "# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        ""
    ]

    final_content = (
        "\n".join(meta_lines) +
        balancer_vless + "\n" +
        "\n".join(vless_lines) +
        "\n\n# === FULL JSON CONFIG WITH BALANCER (Hiddify / Nekobox) ===\n" +
        json_str + "\n"
    )

    return final_content


def build_clash_config(all_configs: list) -> str:
    now_msk = datetime.now(timezone.utc) + timedelta(hours=3)
    now_str = now_msk.strftime("%d.%m.%Y %H:%M")
    count = len(all_configs)

    proxies = []
    proxy_names = []

    for i, cfg in enumerate(all_configs):
        parsed = parse_vless_url(cfg)
        if not parsed:
            continue

        name = build_beautiful_name(parsed, i)

        proxy = {
            "name": name,
            "type": "vless",
            "server": parsed["host"],
            "port": parsed["port"],
            "uuid": parsed["uuid"],
            "udp": True,
            "skip-cert-verify": False,
        }

        if parsed["type"] == "ws":
            proxy["network"] = "ws"
            if parsed.get("path"):
                proxy["ws-opts"] = {"path": parsed["path"]}
            if parsed.get("host_header"):
                proxy.setdefault("ws-opts", {})["headers"] = {"Host": parsed["host_header"]}
        else:
            proxy["network"] = "tcp"

        if parsed["security"] == "reality":
            proxy["tls"] = True
            proxy["servername"] = parsed["sni"] or parsed["host"]
            proxy["client-fingerprint"] = parsed.get("fp", "chrome")
            proxy["reality-opts"] = {
                "public-key": parsed["pbk"],
                "short-id": parsed.get("sid", "")
            }
        elif parsed["security"] == "tls":
            proxy["tls"] = True
            proxy["servername"] = parsed["sni"] or parsed["host"]
            proxy["client-fingerprint"] = parsed.get("fp", "chrome")
        else:
            proxy["tls"] = False

        if parsed.get("flow"):
            proxy["flow"] = parsed["flow"]

        proxies.append(proxy)
        proxy_names.append(name)

    auto_group = {
        "name": "🚀 Auto Best",
        "type": "url-test",
        "proxies": proxy_names,
        "url": "https://www.gstatic.com/generate_204",
        "interval": 300,
        "tolerance": 50,
        "lazy": True
    }

    clash_config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "proxies": proxies,
        "proxy-groups": [
            auto_group,
            {
                "name": "🌍 Select",
                "type": "select",
                "proxies": ["🚀 Auto Best"] + proxy_names
            }
        ],
        "rules": [
            "GEOIP,CN,DIRECT",
            "GEOIP,PRIVATE,DIRECT",
            "MATCH,🌍 Select"
        ]
    }

    header = f"""# Legion VPN Clash Meta Config
# Обновлено: {now_str} МСК
# Серверов: {count}
# Чистые премиальные названия

"""

    import yaml
    return header + yaml.dump(clash_config, allow_unicode=True, sort_keys=False, default_flow_style=False)


def main():
    configs = load_configs(INPUT_FILE)
    print(f"[*] Загружено конфигов: {len(configs)}")

    parsed_list = []
    for cfg in configs:
        parsed = parse_vless_url(cfg)
        if parsed:
            parsed_list.append((cfg, parsed))

    parsed_list.sort(key=lambda x: x[1]["host"])

    print(f"[*] Генерация подписки Legion с чистыми названиями...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(build_subscription([cfg for cfg, _ in parsed_list]))

    print("[*] Генерация Clash конфига...")
    with open("legion_clash.yaml", "w", encoding="utf-8") as f:   # тоже изменил имя файла
        f.write(build_clash_config([cfg for cfg, _ in parsed_list]))

    print("[✓] Готово!")
    print("   → runvpn.txt          (для Hiddify, Nekobox, v2rayN)")
    print("   → legion_clash.yaml   (для Clash / Mihomo / FlClash)")


if __name__ == "__main__":
    main()

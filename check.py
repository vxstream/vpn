import socket
import ssl
import re
import base64
import datetime
import requests
import dns.resolver
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE  = "configs/all_vless.txt"
OUTPUT_FILE = "runvpn.txt"

TIMEOUT = 6
MAX_WORKERS = 50

# ── DNS РФ ─────────────────────────────────────────

def resolve_ru(host):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["77.88.8.8", "77.88.8.1"]
        answer = resolver.resolve(host, "A")
        return answer[0].to_text()
    except:
        return host

# ── ПАРСИНГ ───────────────────────────────────────

def parse_cfg(cfg):
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
    except:
        return None

# ── 1 слой: TCP ───────────────────────────────────

def check_tcp(ip, port):
    try:
        sock = socket.create_connection((ip, port), timeout=TIMEOUT)
        sock.close()
        return True
    except:
        return False

# ── 2 слой: TLS / XRAY ─────────────────────────────

def check_tls(ip, port, sni):
    try:
        sock = socket.create_connection((ip, port), timeout=TIMEOUT)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        sock = ctx.wrap_socket(sock, server_hostname=sni)
        sock.close()

        return True
    except:
        return False

# ── страна ─────────────────────────────────────────

def get_country(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode,country", timeout=5)
        data = r.json()
        return data.get("countryCode", "??"), data.get("country", "Unknown")
    except:
        return "??", "Unknown"

# ── чек ───────────────────────────────────────────

def check(cfg):
    parsed = parse_cfg(cfg)
    if not parsed:
        return None

    host, port, security, sni = parsed
    ip = resolve_ru(host)

    import time
    start = time.time()

    # 1 слой
    if not check_tcp(ip, port):
        return None

    # 2 слой
    if security in ("tls", "reality"):
        if not check_tls(ip, port, sni):
            return None

    latency = int((time.time() - start) * 1000)

    code, country = get_country(ip)

    return {
        "cfg": cfg,
        "latency": latency,
        "code": code,
        "country": country
    }

# ── helpers ───────────────────────────────────────

def strip_tag(cfg):
    return cfg.split("#")[0]

def make_flag(code):
    if len(code) != 2:
        return "🌍"
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)

# ── JSON АВТОВЫБОР ────────────────────────────────

def build_json_block(nodes):
    outbounds = []

    for i, n in enumerate(nodes):
        tag = f"node-{i}"
        outbounds.append({
            "tag": tag,
            "type": "vless",
            "server": parse_cfg(n["cfg"])[0],
            "server_port": parse_cfg(n["cfg"])[1]
        })

    auto = {
        "tag": "auto",
        "type": "selector",
        "outbounds": [o["tag"] for o in outbounds]
    }

    return base64.b64encode(str({
        "outbounds": [auto] + outbounds
    }).encode()).decode()

# ── сборка ────────────────────────────────────────

def build_subscription(nodes):
    now = datetime.datetime.utcnow() + datetime.timedelta(hours=3)
    now_str = now.strftime("%d.%m.%Y %H:%M")

    title = "🇷🇺 RUN VPN"
    title_b64 = base64.b64encode(title.encode()).decode()

    nodes = sorted(nodes, key=lambda x: x["latency"])

    lines = [
        f"#profile-title: base64:{title_b64}",
        "#profile-update-interval: 6",
        "",
        f"# Авто: {now_str}",
        "",
        "#subscription-autoconnect: 1",
        "#subscription-autoconnect-type: lowestdelay",
        "",
    ]

    # JSON авто
    json_block = build_json_block(nodes)
    lines.append(f"#auto-json: base64:{json_block}")
    lines.append("")

    # авто выбор строка
    lines.append("vless://auto#🇪🇺 Автовыбор сервера")
    lines.append("")

    for i, n in enumerate(nodes):
        clean = strip_tag(n["cfg"])
        flag = make_flag(n["code"])
        name = f"{flag} {n['country']} #{i+1} | {n['latency']}ms"
        lines.append(f"{clean}#{name}")

    return "\n".join(lines)

# ── main ──────────────────────────────────────────

def load_configs(path):
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def main():
    configs = load_configs(INPUT_FILE)
    print(f"[*] всего: {len(configs)}")

    working = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(check, cfg): cfg for cfg in configs}

        for f in as_completed(futures):
            res = f.result()
            if not res:
                print("❌ dead")
                continue

            print(f"✅ {res['country']} {res['latency']}ms")
            working.append(res)

    print(f"\n[*] живых: {len(working)}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(build_subscription(working))

    print("done")

if __name__ == "__main__":
    main()

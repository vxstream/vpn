"""
tp.py — одноразово постит новые tg://proxy ссылки в канал.
"""

import re
import os
import json
import requests

# ───────────────────────── CONFIG ─────────────────────────
BOT_TOKEN    = os.environ.get("BOT_TOKEN", "8685204296:AAGyTKHPInqHAJ63OTcgucTpCRlPQBovsFQ")
CHANNEL_ID   = os.environ.get("CHANNEL_ID", "@fameproxies")
SOURCE       = os.environ.get("SOURCE", "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/main/proxy_ru.txt")
MAX_PROXIES  = 20
# ──────────────────────────────────────────────────────────

API = f"https://api.telegram.org/bot{BOT_TOKEN}"


def fetch_source(src: str) -> str:
    if src.startswith("http://") or src.startswith("https://"):
        r = requests.get(src, timeout=15)
        r.raise_for_status()
        return r.text
    with open(src, encoding="utf-8") as f:
        return f.read()


def extract_proxies(text: str) -> list[dict]:
    raw = re.findall(r"tg://proxy\?[^\s\"'<>\]]+", text)
    seen, result = set(), []
    for link in raw:
        if link in seen:
            continue
        seen.add(link)
        result.append({"link": link})
    return result[:MAX_PROXIES]


def build_keyboard(proxies: list[dict]) -> dict:
    buttons = []
    for i, p in enumerate(proxies, 1):
        buttons.append([{
            "text": f"Прокси {i}",
            "url": p["link"],
            "icon_custom_emoji_id": "5769289093221454192"  # 🔗
        }])
    return {"inline_keyboard": buttons}


def send_message(proxies: list[dict]) -> None:
    count = len(proxies)
    text = (
        f'<tg-emoji emoji-id="6039422865189638057">📣</tg-emoji> '
        f'<b>Новые прокси — {count} шт.</b>\n\n'
        f'<tg-emoji emoji-id="6037249452824072506">🔒</tg-emoji> '
        f'Нажмите кнопку ниже, чтобы подключить прокси в Telegram.'
    )

    payload = {
        "chat_id": CHANNEL_ID,
        "text": text,
        "parse_mode": "HTML",
        "reply_markup": json.dumps(build_keyboard(proxies)),
    }

    r = requests.post(f"{API}/sendMessage", json=payload, timeout=15)
    data = r.json()
    if data.get("ok"):
        print(f"✅ Отправлено (id={data['result']['message_id']}), прокси: {count}")
    else:
        print(f"❌ Ошибка: {data.get('description')}")


def main():
    print("🔍 Загружаю источник...")
    try:
        text = fetch_source(SOURCE)
    except Exception as e:
        print(f"❌ Не удалось загрузить: {e}")
        return

    proxies = extract_proxies(text)
    if not proxies:
        print("⚠️  Прокси не найдены.")
        return

    print(f"📋 Найдено: {len(proxies)}")
    send_message(proxies)


if __name__ == "__main__":
    main()

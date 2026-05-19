"""
proxy_poster.py — одноразово постит новые tg://proxy ссылки в канал.
Настройте переменные в блоке CONFIG перед запуском.
"""

import re
import json
import requests

# ───────────────────────── CONFIG ─────────────────────────
BOT_TOKEN    = "8685204296:AAGyTKHPInqHAJ63OTcgucTpCRlPQBovsFQ"          # токен бота
CHANNEL_ID   = "@fameproxies"           # id или username канала

# Источник: URL страницы или путь к .txt файлу с прокси-ссылками
SOURCE       = "https://example.com/proxies"   # или "proxies.txt"

# Макс. кнопок (Telegram разрешает до ~100, но лучше ≤ 20)
MAX_PROXIES  = 20
# ──────────────────────────────────────────────────────────

API = f"https://api.telegram.org/bot{BOT_TOKEN}"


def fetch_source(src: str) -> str:
    """Читает текст из URL или файла."""
    if src.startswith("http://") or src.startswith("https://"):
        r = requests.get(src, timeout=15)
        r.raise_for_status()
        return r.text
    with open(src, encoding="utf-8") as f:
        return f.read()


def extract_proxies(text: str) -> list[dict]:
    """Вытаскивает tg://proxy?... ссылки и парсит параметры."""
    raw = re.findall(r"tg://proxy\?[^\s\"'<>\]]+", text)
    seen, result = set(), []
    for link in raw:
        if link in seen:
            continue
        seen.add(link)
        params = dict(re.findall(r"([a-z]+)=([^&\s\"'<>]+)", link, re.I))
        server = params.get("server", "?")
        port   = params.get("port", "?")
        result.append({"link": link, "server": server, "port": port})
    return result[:MAX_PROXIES]


def build_keyboard(proxies: list[dict]) -> dict:
    """Инлайн-клавиатура: каждая прокси — отдельная кнопка."""
    buttons = []
    for i, p in enumerate(proxies, 1):
        buttons.append([{
            "text": f"Прокси {i} — {p['server']}:{p['port']}",
            "url": p["link"],
            # иконка «ссылка»
            "icon_custom_emoji_id": "5769289093221454192"
        }])
    return {"inline_keyboard": buttons}


def send_message(proxies: list[dict]) -> None:
    count = len(proxies)
    text = (
        '<b>'
        '<tg-emoji emoji-id="6039422865189638057">📣</tg-emoji> '
        f'Появились новые прокси — {count} шт.!'
        '</b>\n\n'
        '<tg-emoji emoji-id="5770552905778456243">🔒</tg-emoji> '
        'Нажмите на кнопку ниже, чтобы добавить прокси в Telegram.'
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
        msg_id = data["result"]["message_id"]
        print(f"✅ Сообщение отправлено (id={msg_id}), {count} прокси.")
    else:
        print(f"❌ Ошибка Telegram API: {data.get('description')}")


def main():
    print("🔍 Загружаю источник...")
    try:
        text = fetch_source(SOURCE)
    except Exception as e:
        print(f"❌ Не удалось загрузить источник: {e}")
        return

    proxies = extract_proxies(text)
    if not proxies:
        print("⚠️  tg://proxy ссылок не найдено.")
        return

    print(f"📋 Найдено прокси: {len(proxies)}")
    for p in proxies:
        print(f"   {p['link']}")

    send_message(proxies)


if __name__ == "__main__":
    main()
  

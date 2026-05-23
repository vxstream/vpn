import requests
import os
import re
import base64
import random
import json
import urllib.parse
from urllib.parse import urlparse, parse_qs, unquote

def get_random_ua():
    try:
        with open('uas.txt', 'r', encoding='utf-8') as f:
            uas = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            if uas:
                return random.choice(uas)
    except Exception:
        pass
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'


# ─────────────────────────── ВАЛИДАЦИЯ ───────────────────────────

HEX_RE = re.compile(r'^[0-9a-fA-F]*$')
# shortId — чётное число hex-символов, либо пустая строка
SHORT_ID_RE = re.compile(r'^[0-9a-fA-F]{0,16}$')

def is_valid_hex(s: str) -> bool:
    return bool(HEX_RE.match(s))

def is_valid_short_id(sid: str) -> bool:
    """shortId: пустая строка или чётное число hex-символов, макс 16."""
    if sid == '':
        return True
    return bool(SHORT_ID_RE.match(sid)) and len(sid) % 2 == 0

def is_valid_uuid(s: str) -> bool:
    uuid_re = re.compile(
        r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )
    return bool(uuid_re.match(s.strip()))

def has_url_encoded_chars(s: str) -> bool:
    """Проверяем наличие незакодированных %20 и подобного мусора."""
    return '%' in s and unquote(s) != s

def validate_vless(url: str) -> tuple[bool, str]:
    """
    Валидация vless://
    Формат: vless://uuid@host:port?params#name
    """
    try:
        # убираем фрагмент
        raw = url.split('#')[0]
        parsed = urlparse(raw)

        uuid = parsed.username or ''
        host = parsed.hostname or ''
        port = parsed.port

        if not is_valid_uuid(uuid):
            return False, f"invalid UUID: {uuid!r}"
        if not host:
            return False, "empty host"
        if not port or not (1 <= port <= 65535):
            return False, f"invalid port: {port}"

        params = parse_qs(parsed.query)

        def p(key): return params.get(key, [''])[0]

        security = p('security')
        stype    = p('type')

        # Проверяем URL-encoded мусор в параметрах
        for key, vals in params.items():
            for v in vals:
                if has_url_encoded_chars(v):
                    return False, f"URL-encoded garbage in param {key!r}: {v!r}"

        # REALITY специфичная валидация
        if security == 'reality':
            pb_key = p('pbk')
            sid    = p('sid')
            fp     = p('fp')

            if not pb_key:
                return False, "REALITY: missing pbk (public key)"
            if not is_valid_hex(pb_key) and len(pb_key) not in (43, 44):
                # pbk может быть base64url или hex
                b64_re = re.compile(r'^[A-Za-z0-9+/\-_]+=*$')
                if not b64_re.match(pb_key):
                    return False, f"REALITY: invalid pbk: {pb_key!r}"
            if not is_valid_short_id(sid):
                return False, f"REALITY: invalid shortId: {sid!r}"
            if not fp:
                return False, "REALITY: missing fingerprint (fp)"

        # TLS
        if security == 'tls':
            alpn = p('alpn')
            # alpn может быть пустым, это ок

        # WebSocket
        if stype == 'ws':
            path = p('path') or '/'
            # path должен начинаться с /
            if path and not path.startswith('/'):
                return False, f"WS: invalid path: {path!r}"

        # gRPC
        if stype == 'grpc':
            srv_name = p('serviceName')
            # просто проверим что нет мусора
            if has_url_encoded_chars(srv_name):
                return False, f"gRPC: invalid serviceName: {srv_name!r}"

        return True, "ok"
    except Exception as e:
        return False, f"parse error: {e}"


def validate_trojan(url: str) -> tuple[bool, str]:
    """
    Валидация trojan://
    Формат: trojan://password@host:port?params#name
    """
    try:
        raw = url.split('#')[0]
        parsed = urlparse(raw)

        password = parsed.username or ''
        host     = parsed.hostname or ''
        port     = parsed.port

        if not password:
            return False, "empty password"
        if not host:
            return False, "empty host"
        if not port or not (1 <= port <= 65535):
            return False, f"invalid port: {port}"

        params = parse_qs(parsed.query)
        def p(key): return params.get(key, [''])[0]

        for key, vals in params.items():
            for v in vals:
                if has_url_encoded_chars(v):
                    return False, f"URL-encoded garbage in param {key!r}: {v!r}"

        security = p('security')
        if security == 'reality':
            sid = p('sid')
            if not is_valid_short_id(sid):
                return False, f"REALITY: invalid shortId: {sid!r}"
            if not p('pbk'):
                return False, "REALITY: missing pbk"

        return True, "ok"
    except Exception as e:
        return False, f"parse error: {e}"


def validate_ss(url: str) -> tuple[bool, str]:
    """
    Валидация ss://
    Форматы:
      ss://BASE64(method:password)@host:port#name
      ss://BASE64(method:password@host:port)#name
    """
    try:
        raw = url.split('#')[0]
        # Пробуем стандартный SIP002: ss://userinfo@host:port
        parsed = urlparse(raw)

        host = parsed.hostname or ''
        port = parsed.port

        if not host:
            return False, "empty host"
        if not port or not (1 <= port <= 65535):
            return False, f"invalid port: {port}"

        # userinfo — base64(method:password)
        userinfo = parsed.username or ''
        if userinfo:
            # может быть urlencoded base64 без padding
            try:
                userinfo_padded = userinfo + '=' * (-len(userinfo) % 4)
                decoded = base64.b64decode(userinfo_padded).decode('utf-8')
                if ':' not in decoded:
                    return False, f"SS: invalid userinfo (no method:pass separator): {decoded!r}"
            except Exception:
                # возможно просто method:password в plain (SIP002 расширение)
                if ':' not in unquote(userinfo):
                    return False, f"SS: cannot decode userinfo: {userinfo!r}"

        return True, "ok"
    except Exception as e:
        return False, f"parse error: {e}"


def validate_vmess(url: str) -> tuple[bool, str]:
    """
    Валидация vmess://
    Формат: vmess://BASE64(json)
    """
    try:
        b64 = url[len('vmess://'):]
        # Добавляем padding
        b64_padded = b64 + '=' * (-len(b64) % 4)
        try:
            decoded = base64.b64decode(b64_padded).decode('utf-8')
        except Exception as e:
            return False, f"base64 decode error: {e}"

        try:
            cfg = json.loads(decoded)
        except Exception as e:
            return False, f"JSON parse error: {e}"

        # Обязательные поля
        required = ['add', 'port', 'id']
        for field in required:
            if field not in cfg:
                return False, f"missing required field: {field!r}"

        host = str(cfg.get('add', ''))
        if not host:
            return False, "empty host (add)"

        try:
            port = int(cfg.get('port', 0))
        except (ValueError, TypeError):
            return False, f"invalid port: {cfg.get('port')!r}"
        if not (1 <= port <= 65535):
            return False, f"port out of range: {port}"

        uid = str(cfg.get('id', ''))
        if not is_valid_uuid(uid):
            return False, f"invalid UUID (id): {uid!r}"

        # Проверяем URL-мусор в строковых полях
        str_fields = ['path', 'host', 'sni', 'scy', 'net', 'type', 'tls']
        for field in str_fields:
            val = str(cfg.get(field, ''))
            if has_url_encoded_chars(val):
                return False, f"URL-encoded garbage in field {field!r}: {val!r}"

        # net (transport)
        valid_nets = {'tcp', 'kcp', 'ws', 'h2', 'quic', 'grpc', 'httpupgrade', ''}
        net = str(cfg.get('net', '')).lower()
        if net not in valid_nets:
            return False, f"unknown network type: {net!r}"

        # tls
        tls = str(cfg.get('tls', '')).lower()
        if tls not in ('', 'tls', 'none'):
            return False, f"invalid tls value: {tls!r}"

        # aid (alterID)
        try:
            aid = int(cfg.get('aid', 0))
        except (ValueError, TypeError):
            return False, f"invalid aid: {cfg.get('aid')!r}"

        return True, "ok"
    except Exception as e:
        return False, f"validation error: {e}"


VALIDATORS = {
    'vless://':  validate_vless,
    'trojan://': validate_trojan,
    'ss://':     validate_ss,
    'vmess://':  validate_vmess,
}

def validate_config(line: str) -> tuple[bool, str]:
    """Определяем тип конфига и валидируем."""
    for prefix, validator in VALIDATORS.items():
        if line.startswith(prefix):
            return validator(line)
    return False, f"unknown protocol prefix"


# ─────────────────────────── СБОР ───────────────────────────

def try_decode_base64_response(text: str) -> str | None:
    """
    Пытаемся определить, является ли ответ base64-encoded.
    Возвращает декодированный текст или None.
    """
    stripped = text.strip()
    # Если в тексте уже есть строки типа vless:// — не трогаем
    protocols = ('vless://', 'vmess://', 'trojan://', 'ss://')
    if any(p in stripped for p in protocols):
        return None
    # Проверяем что строка выглядит как base64
    b64_re = re.compile(r'^[A-Za-z0-9+/\-_\n\r=]+$')
    if b64_re.match(stripped):
        try:
            padded = stripped + '=' * (-len(stripped) % 4)
            decoded = base64.b64decode(padded).decode('utf-8')
            if any(p in decoded for p in protocols):
                return decoded
        except Exception:
            pass
    return None


def collect_configs():
    input_file  = 'reps.txt'
    output_file = 'configs/all_vless.txt'
    invalid_log = 'configs/invalid_configs.txt'

    unique_configs  = {}   # config_str -> True (сохраняем порядок через dict)
    invalid_configs = []   # список (url_source, config, reason)

    os.makedirs('configs', exist_ok=True)

    protocols = ('vless://', 'vmess://', 'trojan://', 'ss://')

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

        urls = []
        for line in raw_lines:
            clean = line.split('#')[0].strip()
            if not clean:
                continue

            is_base64 = False
            if clean.startswith('base64:'):
                is_base64 = True
                clean = clean[7:].strip()
            elif clean.startswith('b64:'):
                is_base64 = True
                clean = clean[4:].strip()

            if clean:
                urls.append((clean, is_base64))

        print(f"Найдено источников: {len(urls)}\n")

        total_added    = 0
        total_invalid  = 0
        total_skipped  = 0

        for url, is_base64 in urls:
            label = url[:80] + ('...' if len(url) > 80 else '')
            tag   = '[base64]' if is_base64 else '[plain]'
            print(f"Загружаю → {label} {tag}")

            try:
                headers = {
                    'User-Agent': get_random_ua(),
                    'Accept':     'text/plain,application/json,*/*',
                    'Accept-Language': 'en-US,en;q=0.9',
                }
                response = requests.get(url, timeout=25, headers=headers)
                response.raise_for_status()
                text = response.text

                # Явно помечено как base64
                if is_base64:
                    try:
                        padded = text.strip() + '=' * (-len(text.strip()) % 4)
                        text = base64.b64decode(padded).decode('utf-8')
                        print(f"  ↳ Ответ декодирован из base64 (явно)")
                    except Exception as e:
                        print(f"  ✗ Ошибка декодирования base64: {e}")
                        continue
                else:
                    # Авто-детект base64
                    decoded = try_decode_base64_response(text)
                    if decoded is not None:
                        text = decoded
                        print(f"  ↳ Ответ авто-декодирован из base64")

                added   = 0
                invalid = 0
                skipped = 0

                for raw_line in text.splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Только нужные протоколы
                    if not line.startswith(protocols):
                        continue

                    # Убираем фрагмент (#комментарий) только из URI, не из vmess json
                    if line.startswith('vmess://'):
                        clean_line = line  # у vmess фрагментов нет в base64-теле
                    else:
                        clean_line = line.split('#')[0].strip()

                    if not clean_line:
                        continue

                    # Дедупликация
                    if clean_line in unique_configs:
                        skipped += 1
                        continue

                    # Валидация
                    ok, reason = validate_config(clean_line)
                    if ok:
                        unique_configs[clean_line] = True
                        added += 1
                    else:
                        invalid_configs.append((url, clean_line, reason))
                        invalid += 1

                total_added   += added
                total_invalid += invalid
                total_skipped += skipped

                print(f"  ✓ Добавлено: {added} | Невалидных: {invalid} | Дублей: {skipped} | Всего: {len(unique_configs)}")

            except requests.exceptions.ConnectionError:
                print(f"  ✗ Ошибка соединения: {url}")
            except requests.exceptions.Timeout:
                print(f"  ✗ Timeout: {url}")
            except requests.exceptions.HTTPError as e:
                print(f"  ✗ HTTP ошибка: {e}")
            except Exception as e:
                print(f"  ✗ Ошибка: {e}")

        # Сохраняем валидные конфиги
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_configs.keys()))

        # Сохраняем лог невалидных
        if invalid_configs:
            with open(invalid_log, 'w', encoding='utf-8') as f:
                f.write(f"Невалидные конфиги ({len(invalid_configs)} шт.)\n")
                f.write("=" * 80 + "\n\n")
                for src, cfg, reason in invalid_configs:
                    f.write(f"Источник : {src}\n")
                    f.write(f"Конфиг   : {cfg[:120]}{'...' if len(cfg) > 120 else ''}\n")
                    f.write(f"Причина  : {reason}\n")
                    f.write("-" * 80 + "\n")

        print("\n" + "=" * 70)
        print("ГОТОВО!")
        print(f"  Валидных конфигов    : {len(unique_configs)}")
        print(f"  Невалидных (отброшено): {len(invalid_configs)}")
        print(f"  Дублей пропущено     : {total_skipped}")
        print(f"  Сохранено в          : {output_file}")
        if invalid_configs:
            print(f"  Лог невалидных       : {invalid_log}")
        print("=" * 70)

    except FileNotFoundError:
        print(f"Файл {input_file!r} не найден!")
    except Exception as e:
        print(f"Критическая ошибка: {e}")


if __name__ == "__main__":
    collect_configs()

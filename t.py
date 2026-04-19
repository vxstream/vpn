import requests
import os
import base64
import re

def is_base64(s: str) -> bool:
    """Проверяет, выглядит ли строка как base64"""
    if not s or len(s) % 4 != 0:
        return False
    # Проверяем, состоит ли строка только из валидных base64 символов
    return bool(re.match(r'^[A-Za-z0-9+/=]+$', s))


def decode_base64_subscribe(content: str) -> list:
    """Декодирует base64-подписку и возвращает список ссылок"""
    try:
        # Убираем возможные пробелы и переносы
        cleaned = content.strip().replace('\n', '').replace(' ', '')
        
        if not is_base64(cleaned):
            return [content]  # если не base64 — возвращаем как есть

        decoded_bytes = base64.b64decode(cleaned)
        decoded_text = decoded_bytes.decode('utf-8')
        
        # Разбиваем на строки (могут быть vless://, vmess://, trojan:// и т.д.)
        links = [line.strip() for line in decoded_text.splitlines() if line.strip()]
        return links
        
    except Exception as e:
        print(f"Ошибка декодирования base64: {e}")
        return [content]  # в случае ошибки возвращаем оригинал


def collect_vless():
    input_file = 'reps.txt'
    output_file = 'configs/all_vless.txt'
    unique_configs = set()  # используем set для автоматического удаления дубликатов

    os.makedirs('configs', exist_ok=True)

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            urls = [line.split('#')[0].strip() for line in f 
                    if line.split('#')[0].strip() and not line.strip().startswith('#')]

        for url in urls:
            print(f"Загружаю: {url}...")
            try:
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    raw_text = response.text.strip()

                    # Проверяем, является ли весь ответ base64-подпиской
                    links = decode_base64_subscribe(raw_text)

                    for link in links:
                        link = link.strip()
                        # Берём только валидные протоколы (можно расширить)
                        if any(link.startswith(proto) for proto in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hysteria2://', 'tuic://']):
                            # Убираем возможный комментарий после #
                            clean_link = link.split('#')[0].strip()
                            if clean_link:
                                unique_configs.add(clean_link)
                else:
                    print(f"Ошибка {response.status_code} при запросе {url}")
            except Exception as e:
                print(f"Ошибка при обработке {url}: {e}")

        # Сохраняем результат
        final_data = '\n'.join(unique_configs)

        with open(output_file, 'w', encoding='utf-8') as out:
            out.write(final_data)

        print(f"\nГотово! Собрано уникальных конфигов: {len(unique_configs)}")
        print(f"Файл сохранён: {output_file}")

    except FileNotFoundError:
        print(f"Файл {input_file} не найден.")
    except Exception as e:
        print(f"Критическая ошибка: {e}")


if __name__ == "__main__":
    collect_vless()

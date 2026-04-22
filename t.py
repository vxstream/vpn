import requests
import os
import re
import base64
import random

def get_random_ua():
    try:
        with open('uas.txt', 'r', encoding='utf-8') as f:
            uas = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            if uas:
                return random.choice(uas)
    except Exception:
        pass
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'

def collect_vless():
    input_file = 'reps.txt'
    output_file = 'configs/all_vless.txt'
    unique_configs = set()

    os.makedirs('configs', exist_ok=True)

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            
            urls = []
            for line in raw_lines:
                # Убираем inline комментарии после #
                clean = line.split('#')[0].strip()
                if not clean:
                    continue
                
                # Проверяем префикс base64:
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

        for url, is_base64 in urls:
            print(f"Загружаю → {url[:80]}{'...' if len(url) > 80 else ''} {'[base64]' if is_base64 else '[plain]'}")
            try:
                headers = {
                    'User-Agent': get_random_ua(),
                    'Accept': 'text/plain,application/json,*/*',
                    'Accept-Language': 'en-US,en;q=0.9',
                }
                response = requests.get(url, timeout=25, headers=headers)
                response.raise_for_status()
                text = response.text

                # Если помечено как base64 — декодируем ответ
                if is_base64:
                    try:
                        text = base64.b64decode(text).decode('utf-8')
                        print(f"  ↳ Ответ декодирован из base64")
                    except Exception as e:
                        print(f"  ✗ Ошибка декодирования base64 ответа: {e}")
                        continue

                added = 0
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Берём только vless://
                    if line.startswith('vless://'):
                        # Убираем всё после # (комментарий)
                        clean = line.split('#', 1)[0].strip()
                        if clean:
                            unique_configs.add(clean)
                            added += 1

                print(f"  ✓ Добавлено: {added} | Всего уникальных: {len(unique_configs)}")

            except Exception as e:
                print(f"  ✗ Ошибка: {e}")

        # Сохраняем результат
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_configs))

        print("\n" + "="*70)
        print(f"ГОТОВО!")
        print(f"Всего собрано уникальных VLESS конфигов: {len(unique_configs)}")
        print(f"Сохранено в: {output_file}")
        print("="*70)

    except Exception as e:
        print(f"Критическая ошибка: {e}")


if __name__ == "__main__":
    collect_vless()

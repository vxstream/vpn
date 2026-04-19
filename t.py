import requests
import os
import re

def collect_vless():
    input_file = 'reps.txt'
    output_file = 'configs/all_vless.txt'
    unique_configs = set()

    os.makedirs('configs', exist_ok=True)

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            urls = [line.split('#')[0].strip() for line in f 
                    if line.split('#')[0].strip() and not line.strip().startswith('#')]

        print(f"Найдено источников: {len(urls)}\n")

        for url in urls:
            print(f"Загружаю → {url}")
            try:
                response = requests.get(url, timeout=25)
                response.raise_for_status()
                text = response.text

                added = 0
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Берём только vless:// (можно добавить другие протоколы позже)
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

import requests
import os

def collect_vless():
    input_file = 'reps.txt'
    output_file = 'configs/all_vless.txt'
    unique_configs = []

    # Создаём директорию если нет
    os.makedirs('configs', exist_ok=True)

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            # Читаем ссылки из репозитория, игнорируя комменты и пустые строки
            urls = [line.split('#')[0].strip() for line in f if line.split('#')[0].strip()]

        for url in urls:
            print(f"Загружаю: {url}...")
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    # Разбиваем содержимое по пробелам ИЛИ переносам строк
                    # filter(None, ...) уберет пустые элементы
                    raw_content = response.text.replace('\n', ' ').split(' ')

                    for item in raw_content:
                        item = item.strip()
                        if item.startswith('vless://'):
                            # Очищаем саму ссылку от комментария в конце, если он есть
                            clean_vless = item.strip()
                            if clean_vless not in unique_configs:
                                unique_configs.append(clean_vless)
                else:
                    print(f"Ошибка {response.status_code}")
            except Exception as e:
                print(f"Ошибка при обработке {url}: {e}")

        # Собираем всё в одну строку, где каждый конфиг на новой строке
        final_data = '\n'.join(unique_configs)

        with open(output_file, 'w', encoding='utf-8') as out:
            out.write(final_data)

        print(f"\nГотово! Собрано уникальных строк: {len(unique_configs)}")
        print(f"Файл {output_file} готов к использованию.")

    except FileNotFoundError:
        print(f"Файл {input_file} не найден.")

if __name__ == "__main__":
    collect_vless()

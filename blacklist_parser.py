import requests
import base64
import os

# Ссылки по умолчанию (на случай, если файла sources.txt нет)
DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"
]

# Поддерживаемые протоколы
SUPPORTED_PROTOCOLS = ('vmess://', 'vless://', 'ss://', 'ssr://', 'trojan://', 'tuic://', 'hysteria2://')

def decode_base64_content(content):
    """Пытается декодировать Base64. Если не выходит, возвращает как обычный текст."""
    try:
        # Добавляем выравнивание для корректного декодирования Base64
        padded = content.strip() + '=' * (-len(content.strip()) % 4)
        return base64.b64decode(padded).decode('utf-8', errors='ignore')
    except Exception:
        return content

def main():
    urls = []
    
    # Читаем ссылки из специального файла sources.txt, если он существует
    if os.path.exists("sources.txt"):
        with open("sources.txt", "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    # Если файл пуст или его нет, используем дефолтные источники
    if not urls:
        print("Файл sources.txt не найден или пуст. Используем источники по умолчанию.")
        urls = DEFAULT_SOURCES

    proxies = set()

    for url in urls:
        print(f"Парсинг подписки: {url}")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Декодируем содержимое
            decoded_text = decode_base64_content(response.text)
            
            # Ищем строки с VPN-протоколами
            for line in decoded_text.splitlines():
                line = line.strip()
                if line.startswith(SUPPORTED_PROTOCOLS):
                    proxies.add(line)
                    
        except Exception as e:
            print(f"Ошибка при обработке {url}: {e}")

    # Сохраняем в открытом виде (построчно)
    with open("proxies.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(proxies))
    
    # Сохраняем в формате Base64 (стандартный формат для большинства VPN-клиентов)
    encoded_proxies = base64.b64encode("\n".join(proxies).encode('utf-8')).decode('utf-8')
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(encoded_proxies)

    print(f"\nУспешно собрано уникальных серверов: {len(proxies)}")
    print("Результаты сохранены в файлы: 'proxies.txt' (текст) и 'sub.txt' (Base64).")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import requests
import base64
import json
import re
import hashlib
import socket
from urllib.parse import urlparse, urlunparse, parse_qs
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Конфигурация ---
OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

MAIN_SUB = OUTPUT_DIR / "sub.txt"
IOS_SUB = OUTPUT_DIR / "sub_ios.txt"
SINGBOX_SUB = OUTPUT_DIR / "sub_singbox.json"
STATS = OUTPUT_DIR / "stats.json"

SOURCES_FILE = Path("sources/sources.txt")

REQUEST_DELAY = 1.5
FETCH_TIMEOUT = 10
CHECK_TIMEOUT = 5
MAX_WORKERS = 40

SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

# --- Вспомогательные функции ---
def fetch(url):
    """Загрузка содержимого URL."""
    try:
        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()
        return resp.content
    except Exception:
        return None

def tcp_check(link):
    """Проверка TCP‑подключения к хосту и порту."""
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CHECK_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def full_check(link):
    """Проверка HTTP‑ответа через прокси‑подключение."""
    if not tcp_check(link):
        return False
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        # Для SOCKS‑прокси этот метод не подходит, пропускаем
        if "socks" in link.lower():
            return True  # считаем, что TCP прошёл — уже неплохо
        proxies = {
            "http": None,
            "https": f"http://{host}:{port}"
        }
        r = requests.get(
            "https://www.gstatic.com/generate_204",
            proxies=proxies,
            timeout=CHECK_TIMEOUT,
            allow_redirects=False
        )
        return r.status_code in (204, 200)
    except Exception:
        return False

def config_hash(link):
    """MD5‑хеш ссылки без фрагмента (для дедупликации)."""
    try:
        p = urlparse(link)
        clean = p._replace(fragment="").geturl()
        return hashlib.md5(clean.encode()).hexdigest()
    except Exception:
        return None

def rename_config(link):
    """Присвоение читаемого имени конфигурации."""
    try:
        protocol = link.split("://")[0].upper()
        transport = ""
        lower = link.lower()
        if "reality" in lower:
            transport = "Reality"
        elif "ws" in lower:
            transport = "WS"
        elif "grpc" in lower:
            transport = "gRPC"
        elif "hysteria2" in lower:
            transport = "Hysteria2"

        parsed = urlparse(link)
        qs = parse_qs(parsed.query)
        sni = qs.get('sni', [''])[0] or qs.get('host', [''])[0]

        if transport:
            name = f"{protocol}-{transport}-{sni}-#Kfg"
        else:
            name = f"{protocol}-#Kfg"
        name = re.sub(r'-+', '-', name).strip('-')

        if link.startswith("vmess://"):
            # декодируем vmess
            data = json.loads(base64.b64decode(link[8:] + "===").decode(errors='ignore'))
            data["ps"] = name
            encoded = base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode().rstrip("=")
            return "vmess://" + encoded
        else:
            return urlunparse(parsed._replace(fragment=name))
    except Exception:
        # если что‑то пошло не так — возвращаем как было
        return link

def priority_key(link):
    """Приоритет для сортировки (чем выше, тем лучше)."""
    lower = link.lower()
    if 'hysteria2' in lower:
        return 100
    if 'reality' in lower:
        return 90
    if 'trojan' in lower:
        return 70
    if 'vless' in lower:
        return 50
    return 20

# --- Главная функция ---
def main():
    print("🚀 Kfg-Lists Parser запущен")

    # 1. Инициализируем stats.json (чтобы файл точно существовал)
    stats = {
        "total": 0,
        "last_update": datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        "stages": {}
    }
    with open(STATS, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)

    # 2. Читаем источники
    try:
        with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
            sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"❌ Файл источников {SOURCES_FILE} не найден")
        return

    # 3. Скачиваем конфиги
    all_configs = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        future_to_src = {executor.submit(fetch, src): src for src in sources}
        for future in as_completed(future_to_src):
            src = future_to_src[future]
            content = future.result()
            if not content:
                continue
            try:
                text = content.decode('utf-8', errors='ignore')
            except Exception:
                continue

            if 't.me' in src:
                # Telegram / plain text
                pat = r'(vmess://|vless://|trojan://|ss://|ssr://|hysteria2://|tuic://)[^\s<>"\']+'
                all_configs.extend(re.findall(pat, text))
            else:
                # обычный sub файл
                lines = [
                    line.strip() for line in text.splitlines()
                    if any(line.startswith(p + "://") for p in SUPPORTED)
                ]
                all_configs.extend(lines)

    print(f"📥 Сырых конфигов: {len(all_configs)}")

    # 4. Дедупликация
    unique_map = {}
    for link in all_configs:
        if any(link.startswith(p + "://") for p in SUPPORTED):
            h = config_hash(link)
            if h and h not in unique_map:
                unique_map[h] = link
    unique_raw = unique_map
    print(f"🧹 Уникальных: {len(unique_raw)}")

    # 5. TCP проверка
    candidates = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_link = {executor.submit(tcp_check, link): link for link in unique_raw.values()}
        for future in as_completed(future_to_link):
            if future.result():
                candidates.append(future_to_link[future])
    print(f"🔍 TCP доступных: {len(candidates)}")

    # 6. Полная проверка (HTTP‑туннель)
    working = []
    # Ограничиваем количество полных проверок для скорости
    to_check = candidates[:3000]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_link = {executor.submit(full_check, link): link for link in to_check}
        for future in as_completed(future_to_link):
            if future.result():
                working.append(future_to_link[future])
    print(f"✅ Полностью рабочих: {len(working)}")

    # 7. Переименование и сортировка
    valid = [rename_config(link) for link in working]
    valid.sort(key=priority_key, reverse=True)

    android_configs = valid
    ios_configs = valid[:50]

    # Fallback, если слишком мало рабочих
    if len(android_configs) < 400:
        fallback = [rename_config(link) for link in candidates[:2000]]
        android_configs = fallback
        ios_configs = fallback[:50]
        print(f"⚠️ Использован fallback, итого: {len(android_configs)}")

    # 8. Сохранение файлов
    MAIN_SUB.write_text(base64.b64encode('\n'.join(android_configs).encode()).decode(), encoding='utf-8')
    IOS_SUB.write_text(base64.b64encode('\n'.join(ios_configs).encode()).decode(), encoding='utf-8')

    singbox_data = {
        "outbounds": [
            {
                "type": "urltest",
                "tag": "Kfg",
                "outbounds": android_configs
            }
        ]
    }
    with open(SINGBOX_SUB, 'w', encoding='utf-8') as f:
        json.dump(singbox_data, f, indent=2)

    # 9. Обновление статистики
    stats["total"] = len(android_configs)
    stats["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    stats["stages"] = {
        "raw": len(all_configs),
        "unique": len(unique_raw),
        "tcp_alive": len(candidates),
        "full_alive": len(working),
        "final": len(android_configs)
    }
    with open(STATS, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)

    print(f"🎉 Готово! Всего конфигов: {len(android_configs)}")

if __name__ == "__main__":
    main()

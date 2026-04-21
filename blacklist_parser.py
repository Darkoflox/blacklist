import requests
import base64
import json
import re
import time
import hashlib
import socket
from urllib.parse import urlparse, urlunparse
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

MAIN_SUB = OUTPUT_DIR / "sub_black.txt"      # Основная подписка для чёрных списков
IOS_SUB  = OUTPUT_DIR / "sub_ios_black.txt"
SINGBOX_SUB = OUTPUT_DIR / "sub_singbox_black.json"
STATS = OUTPUT_DIR / "stats_black.json"

SOURCES_FILE = Path("sources/sources.txt")

REQUEST_DELAY = 1.5
FETCH_TIMEOUT = 10
CHECK_TIMEOUT = 5
MAX_WORKERS = 40

SUPPORTED = ["vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "tuic"]

def fetch(url):
    try:
        return requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=FETCH_TIMEOUT).content
    except:
        return None

def tcp_check(link):
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CHECK_TIMEOUT)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def full_check(link):
    if not tcp_check(link):
        return False
    try:
        p = urlparse(link)
        host = p.hostname
        port = p.port or 443
        proxies = {"http": None, "https": f"http://{host}:{port}" if "socks" not in link.lower() else None}
        r = requests.get("https://www.gstatic.com/generate_204", proxies=proxies, timeout=CHECK_TIMEOUT, allow_redirects=False)
        return r.status_code in (204, 200)
    except:
        return False

def config_hash(link):
    try:
        p = urlparse(link)
        return hashlib.md5(p._replace(fragment="").geturl().encode()).hexdigest()
    except:
        return None

def rename_config(link):
    protocol = link.split("://")[0].upper()
    transport = ""
    if "reality" in link.lower(): transport = "Reality"
    elif "ws" in link.lower(): transport = "WS"
    elif "grpc" in link.lower(): transport = "gRPC"
    elif "hysteria2" in link.lower(): transport = "Hysteria2"

    try:
        parsed = urlparse(link)
        sni = parse_qs(parsed.query).get('sni', [''])[0] or parse_qs(parsed.query).get('host', [''])[0]
    except:
        sni = ""

    name = f"{protocol}-{transport}-{sni}-Black-#Kfg-analyzer" if transport else f"{protocol}-Black-#Kfg-analyzer"
    name = re.sub(r'-+', '-', name).strip('-')

    if link.startswith("vmess://"):
        try:
            data = json.loads(base64.b64decode(link[8:] + "===").decode(errors='ignore'))
            data["ps"] = name
            return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode().rstrip("=")
        except:
            pass
    else:
        try:
            parsed = urlparse(link)
            return urlunparse(parsed._replace(fragment=name))
        except:
            pass
    return link

def priority_key(link):
    lower = link.lower()
    if 'hysteria2' in lower: return 100
    if 'reality' in lower: return 90
    if 'trojan' in lower: return 70
    if 'vless' in lower: return 50
    return 20

def main():
    print("🚀 Blacklist Parser v7.3 (для чёрных списков / Wi-Fi) запущен")

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    print(f"📋 Всего источников: {len(sources)}")

    all_configs = []
    with ThreadPoolExecutor(max_workers=15) as executor:
        future_to_src = {executor.submit(fetch, src): src for src in sources}
        for future in as_completed(future_to_src):
            src = future_to_src[future]
            content = future.result()
            if content:
                text = content.decode('utf-8', errors='ignore')
                if 't.me' in src:
                    pat = r'(vmess://|vless://|trojan://|ss://|ssr://|hysteria2://|tuic://)[^\s<>"\']+'
                    found = re.findall(pat, text)
                    all_configs.extend(found)
                    print(f"   ↳ TG: найдено {len(found)}")
                else:
                    lines = [l.strip() for l in text.splitlines() if any(l.startswith(p + "://") for p in SUPPORTED)]
                    all_configs.extend(lines)
                    print(f"   ↳ File: {len(lines)}")

    unique_raw = {config_hash(link): link for link in all_configs if any(link.startswith(p + "://") for p in SUPPORTED)}
    print(f"📦 Уникальных конфигов: {len(unique_raw)}")

    # Этап 1 — TCP
    print("🔍 Этап 1: Быстрая TCP-проверка...")
    candidates = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_link = {executor.submit(tcp_check, link): link for link in unique_raw.values()}
        for future in as_completed(future_to_link):
            if future.result():
                candidates.append(future_to_link[future])

    print(f"   Прошло TCP: {len(candidates)}")

    # Этап 2 — лёгкая проверка
    print("🔍 Этап 2: Полная проверка...")
    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_link = {executor.submit(full_check, link): link for link in candidates[:3000]}
        for future in as_completed(future_to_link):
            if future.result():
                working.append(future_to_link[future])

    print(f"✅ Прошло проверку: {len(working)}")

    valid = [rename_config(link) for link in working]
    valid.sort(key=priority_key, reverse=True)

    android_configs = valid
    ios_configs = valid[:50]

    if len(android_configs) < 400:
        print("⚠️ Мало рабочих — беру из TCP-кандидатов")
        fallback = [rename_config(link) for link in candidates[:2000]]
        android_configs = fallback
        ios_configs = fallback[:50]

    MAIN_SUB.write_text(base64.b64encode('\n'.join(android_configs).encode()).decode())
    IOS_SUB.write_text(base64.b64encode('\n'.join(ios_configs).encode()).decode())

    with open(SINGBOX_SUB, 'w', encoding='utf-8') as f:
        json.dump({"outbounds": [{"type": "urltest", "tag": "Kfg-Black", "outbounds": android_configs}]}, f, indent=2)

    stats = {
        "total_android": len(android_configs),
        "ios_top50": len(ios_configs),
        "last_update": datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    }
    json.dump(stats, open(STATS, 'w'), indent=2)

    print(f"✅ Blacklist готов! Android: {len(android_configs)} | iOS: {len(ios_configs)}")

if __name__ == "__main__":
    main()

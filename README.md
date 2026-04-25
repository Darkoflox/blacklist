# Wi‑Fi Parser (ЧС)

Генератор подписок для домашних Wi‑Fi сетей.  
Собирает конфигурации из публичных источников и Telegram‑каналов, проверяет их работоспособность и формирует удобные списки для импорта в VPN‑клиенты.

## 🚀 Возможности

- Сбор из URL‑подписок (`sources.txt`) и Telegram‑каналов (`sources_tg.txt`).
- Двухэтапная проверка TCP+TLS.
- Без фильтрации по странам – используются любые доступные серверы.
- Ограничения: Android ≤5000 конфигураций, iOS ≤300.
- Автоматическое обновление каждые 6 часов через GitHub Actions.

## 🔗 Готовые подписки

- Android: `https://raw.githubusercontent.com/Darkoflox/wifi-parser/main/sub_android.txt`
- iOS: `https://raw.githubusercontent.com/Darkoflox/wifi-parser/main/sub_ios.txt`
- Все проверенные: `https://raw.githubusercontent.com/Darkoflox/wifi-parser/main/sub_all_checked.txt`

## 📦 Структура

- `parser.py` – основной скрипт.
- `sources.txt` – список URL‑источников.
- `sources_tg.txt` – список Telegram‑каналов (опционально).
- `requirements.txt` – зависимости.
- `.github/workflows/update.yml` – автоматизация.

## ⚙️ Запуск вручную

```bash
pip install -r requirements.txt
python parser.py --threads 40 --strategy diverse

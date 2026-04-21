import requests
import datetime
import sys

# Список самых надежных и обновляемых источников в мире
# Если первый упадет, скрипт автоматически попробует следующий
URLS = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://adaway.org/hosts.txt",
    "https://someonewhocares.org/hosts/hosts"
]

hosts_content = None

# Пытаемся скачать список, перебирая источники
for url in URLS:
    try:
        print(f"Попытка загрузки из: {url}")
        # Устанавливаем timeout 10 секунд, чтобы скрипт не зависал бесконечно
        response = requests.get(url, timeout=10)
        response.raise_for_status() # Проверка на 404 и другие ошибки
        hosts_content = response.text
        print("Успешно загружено!")
        break  # Если успешно скачали, выходим из цикла поиска
    except requests.exceptions.RequestException as e:
        print(f"Ошибка при загрузке {url}: {e}")

# Если все ссылки из списка перестали работать (что маловероятно)
if not hosts_content:
    print("Критическая ошибка: Не удалось загрузить ни один из списков.")
    sys.exit(1) # Завершаем с ошибкой, чтобы Github Actions загорелся красным

lines = hosts_content.splitlines()
domains = set() # Используем set (множество) для автоматического удаления дубликатов

# Список системных доменов, которые категорически нельзя блокировать
WHITELIST = {
    'localhost', 'localhost.localdomain', 'local',
    'broadcasthost', 'ip6-localhost', 'ip6-loopback',
    '0.0.0.0'
}

# Извлекаем домены
for line in lines:
    line = line.strip()
    # Пропускаем пустые строки и строки, начинающиеся с комментария
    if not line or line.startswith('#'):
        continue
    
    # Отрезаем комментарии, если они написаны после домена (разделитель #)
    line = line.split('#')[0].strip()
    
    parts = line.split()
    # Ищем строки, где есть как минимум IP и домен
    if len(parts) >= 2:
        ip = parts[0]
        domain = parts[1].lower() # Приводим к нижнему регистру
        
        # Берем только блокирующие записи
        if ip in ['0.0.0.0', '127.0.0.1'] and domain not in WHITELIST:
            domains.add(domain)

# Сортируем список по алфавиту для удобства и красивых коммитов в Git
sorted_domains = sorted(list(domains))

# Получаем текущую дату и время
current_datetime = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

# Формируем итоговый текст с заголовком
output_content = f"""# Title: BlockList
# Description: This is a list of domains to be blocked, updated on {current_datetime}
# Last modified: {current_datetime}
# Expires: 1 day (server time)
# Domain count: {len(sorted_domains)}
#==================================================================\n"""
output_content += "\n".join(sorted_domains)

# Записываем результат в файл
try:
    with open("blacklist.txt", "w", encoding="utf-8") as file:
        file.write(output_content)
    print(f"Готово! Файл blacklist.txt успешно сгенерирован.")
    print(f"Всего уникальных доменов добавлено: {len(sorted_domains)}")
except IOError as e:
    print(f"Ошибка при сохранении файла: {e}")
    sys.exit(1)

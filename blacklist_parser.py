import requests
import datetime

# Новый рабочий URL для hosts файла
url = "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts.txt"

# Загружаем содержимое файла
try:
    response = requests.get(url)
    response.raise_for_status()  # Остановит скрипт с ошибкой, если сайт вернет 404 или другую ошибку
    hosts_content = response.text
except Exception as e:
    print(f"Ошибка при загрузке: {e}")
    exit(1)

lines = hosts_content.split('\n')
domains = []

# Извлекаем домены, пропуская комментарии и пустые строки
for line in lines:
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    
    parts = line.split()
    # Убеждаемся, что в строке есть как минимум IP и домен
    if len(parts) >= 2:
        ip = parts[0]
        domain = parts[1]
        # Берем только блокирующие записи (0.0.0.0 или 127.0.0.1)
        if ip in ['0.0.0.0', '127.0.0.1'] and domain not in ['localhost', 'localhost.localdomain', 'local', 'broadcasthost']:
            domains.append(domain)

# Получаем текущую дату и время
current_datetime = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

# Формируем итоговый текст
output_content = f"""# Title: BlockList
# Description: This is a list of domains to be blocked, updated on {current_datetime}
# Last modified: {current_datetime}
# Expires: 1 day (server time)
# Domain count: {len(domains)}
#==================================================================\n"""
output_content += "\n".join(domains)

# Записываем все в файл
with open("blacklist.txt", "w", encoding="utf-8") as file:
    file.write(output_content)

print(f"blacklist.txt file has been generated successfully. Total domains: {len(domains)}")

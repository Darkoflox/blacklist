import requests
import datetime

# URL for the hosts file
url = "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/Ultimate.Hosts.Blacklist/master/hosts.txt"

# Get the content of the hosts file
response = requests.get(url)
hosts_content = response.text

# Split the content into lines
lines = hosts_content.split('\n')

# Find the start and end of the relevant section
start_index = -1
end_index = -1
for i, line in enumerate(lines):
    if "Start of entries" in line:
        start_index = i + 1
    elif "End of entries" in line:
        end_index = i
        break

# Extract the domains
if start_index != -1 and end_index != -1:
    domain_lines = lines[start_index:end_index]
    domains = [line.split()[1] for line in domain_lines if len(line.split()) > 1]
else:
    domains = []

# Get the current date and time
current_datetime = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

# Format the output
output_content = f"""# Title: BlockList
# Description: This is a list of domains to be blocked, updated on {current_datetime}
# Last modified: {current_datetime}
# Expires: 1 day (server time)
# Domain count: {len(domains)}
#==================================================================\n"""
output_content += "\n".join(domains)

# Write the formatted content to blacklist.txt
with open("blacklist.txt", "w") as file:
    file.write(output_content)

print("blacklist.txt file has been generated successfully.")

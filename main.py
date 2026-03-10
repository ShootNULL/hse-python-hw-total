import os

import requests
import pandas as pd
import matplotlib.pyplot as plt
import json

# ===============================
# 1. Загрузка логов Suricata
# ===============================

with open("suricata_logs.json", "r") as f:
    logs = json.load(f)

df = pd.DataFrame(logs)

print("Loaded logs:")
print(df)

# ===============================
# 2. Анализ подозрительных IP
# ===============================

ip_counts = df["src_ip"].value_counts()

print("\nIP activity:")
print(ip_counts)

# подозрительный IP если >3 запросов
suspicious_ips = ip_counts[ip_counts > 3]

# ===============================
# 3. Проверка IP через API
# ===============================

api_url = "https://www.virustotal.com/api/v3/ip_addresses/"
API_KEY = os.getenv("VT_API_KEY")

results = []

for ip in suspicious_ips.index:

    print(f"\nChecking IP: {ip}")

    headers = {"x-apikey": API_KEY}

    try:
        r = requests.get(api_url + ip, headers=headers)

        if r.status_code == 200:
            data = r.json()

            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]

        else:
            malicious = "unknown"

    except:
        malicious = "error"

    results.append({
        "ip": ip,
        "requests": ip_counts[ip],
        "malicious_score": malicious
    })

# ===============================
# 4. Реагирование
# ===============================

for r in results:
    if r["requests"] > 3:
        print(f"Threat detected! Simulating block for IP {r['ip']}")

# ===============================
# 5. Сохранение отчёта
# ===============================

report = pd.DataFrame(results)

report.to_csv("report.csv", index=False)

print("\nReport saved to report.csv")

# ===============================
# 6. Построение графика
# ===============================

ip_counts.plot(kind="bar")

plt.title("Top IP activity")
plt.xlabel("IP")
plt.ylabel("Requests")

plt.savefig("chart.png")

print("Chart saved to chart.png")

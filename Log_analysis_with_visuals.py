import re
import pandas as pd
import matplotlib.pyplot as plt

log_file = "alert_full.txt"  

# Regular expression 
regex = r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+).*?\[\*\*\] \[(\d+):(\d+):(\d+)\] (.*?) \[\*\*\].*?\{(.*?)\} (.*?) -> (.*)"

data = []
try:
    with open(log_file, "r") as f:
        for line in f:
            match = re.match(regex, line)
            if match:
                timestamp = match.group(1)
                gid = int(match.group(2))
                sid = int(match.group(3))
                rev = int(match.group(4))
                message = match.group(5)
                protocol = match.group(6)
                src_ip_port = match.group(7)
                dst_ip_port = match.group(8)

                src_ip, src_port = src_ip_port.split(":") if ":" in src_ip_port else (src_ip_port, None)
                dst_ip, dst_port = dst_ip_port.split(":") if ":" in dst_ip_port else (dst_ip_port, None)

                data.append([timestamp, gid, sid, rev, message, protocol, src_ip, src_port, dst_ip, dst_port])

except FileNotFoundError:
    print(f"Error: File '{log_file}' not found. Please check the file path.")
    exit()

df = pd.DataFrame(data, columns=["Timestamp", "GID", "SID", "Rev", "Message", "Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port"])

# Convert timestamps with explicit format
df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%m/%d-%H:%M:%S.%f')

# --- Analysis and Visualization ---

# 1. Alert Frequency Over Time:
alerts_by_time = df.resample('1Min', on='Timestamp')['SID'].count()
alerts_by_time.plot(kind='line')
plt.title('Alert Frequency Over Time (Per Minute)')
plt.ylabel('Number of Alerts')
plt.show()

# 2. Alert Type Distribution (by SID):
sid_counts = df['SID'].value_counts()
sid_counts.plot(kind='bar')
plt.title('Alert Distribution by SID')
plt.xlabel('SID')
plt.ylabel('Number of Alerts')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()

# 3. Protocol Distribution:
protocol_counts = df['Protocol'].value_counts()
protocol_counts.plot(kind='pie', autopct='%1.1f%%')
plt.title('Distribution of Protocols in Alerts')
plt.ylabel('')
plt.show()


# 4. Top Source IPs Triggering Alerts:
src_ip_counts = df['Source IP'].value_counts().head(10)
src_ip_counts.plot(kind='bar')
plt.title('Top Source IPs Triggering Alerts')
plt.xlabel('Source IP')
plt.ylabel('Number of Alerts')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()

# 4. Top Destination Ports Triggering Alerts
dst_port_counts = df['Destination Port'].value_counts().head(10)
dst_port_counts.plot(kind='bar')
plt.title('Top Destination Ports Triggering Alerts')
plt.xlabel('Destination Port')
plt.ylabel('Number of Alerts')
plt.xticks(rotation=45, ha='right') 
plt.tight_layout() # 
plt.show()
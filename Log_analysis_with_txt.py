import re
import pandas as pd
import matplotlib.pyplot as plt

log_file = "alert_full.txt" 


def analyze_snort_log(log_file):

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
        return f"Error: File '{log_file}' not found."  # Return error message


    df = pd.DataFrame(data, columns=["Timestamp", "GID", "SID", "Rev", "Message", "Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port"])
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%m/%d-%H:%M:%S.%f')


    # --- Text-based Output ---

    output = ""

    # 1. Alert Frequency Over Time:
    alerts_by_time = df.resample('1Min', on='Timestamp')['SID'].count()
    output += "Alert Frequency Over Time (Per Minute):\n" + alerts_by_time.to_string() + "\n\n"


    # 2. Alert Type Distribution (by SID):
    sid_counts = df['SID'].value_counts()
    output += "Alert Distribution by SID:\n" + sid_counts.to_string() + "\n\n"

    # 3. Protocol Distribution:
    protocol_counts = df['Protocol'].value_counts()
    output += "Distribution of Protocols in Alerts:\n" + protocol_counts.to_string() + "\n\n"

    # 4. Top Source IPs Triggering Alerts:
    src_ip_counts = df['Source IP'].value_counts().head(10)
    output += "Top Source IPs Triggering Alerts:\n" + src_ip_counts.to_string() + "\n\n"

    # 5. Top Destination Ports Triggering Alerts
    dst_port_counts = df['Destination Port'].value_counts().head(10)
    output += "Top Destination Ports Triggering Alerts:\n" + dst_port_counts.to_string() + "\n\n"

    return output  # Return the text output



if __name__ == "__main__":
    log_file = "alert_full.txt"  
    analysis_results = analyze_snort_log(log_file)
    print(analysis_results) 
   
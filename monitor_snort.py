import time
import os
import re

# 全局變數來維護 SID 計數器
sid_counter = 1000020

def extract_ip(alert_line):
    """根據 Snort 警報格式提取 IP 地址。"""
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', alert_line)
    if match:
        return match.group(1)
    return None

def clear_whitelist():
    """在開始時清空 whitelist.rules 文件。"""
    with open('/etc/snort/rules/whitelist.rules', 'w') as f:
        f.write('')  # 清空文件內容

def update_whitelist(triggered_ips):
    """更新 whitelist.rules 文件，將新觸發的 IP 添加到白名單。"""
    global sid_counter
    with open('/etc/snort/rules/whitelist.rules', 'a') as f:
        for ip in triggered_ips:
            f.write(f'pass ip {ip} any -> any any (msg:"Allow all traffic from triggered IP"; sid:{sid_counter}; rev:1;)\n')
            sid_counter += 1  # 為每個新 IP 生成唯一 SID

def monitor_alerts():
    alert_file = '/var/log/snort/alert'
    triggered_ips = set()
    last_position = 0

    # 清空 whitelist.rules 文件
    clear_whitelist()

    while True:
        try:
            with open(alert_file, 'r') as f:
                f.seek(last_position)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    if "1000010" in line:  # 檢查特定規則 ID
                        triggered_ip = extract_ip(line)
                        if triggered_ip:
                            triggered_ips.add(triggered_ip)
                            update_whitelist(triggered_ips)
                            triggered_ips.clear()  # 清空觸發的 IP 列表，只在更新後清空
                            os.system('sudo snort -c /etc/snort/snort.conf -R')  # 重新加載 Snort 規則
                last_position = f.tell()  # 更新文件指針位置
        except Exception as e:
            print(f"Error: {e}")

        time.sleep(10)  # 每 10 秒鐘檢查一次文件

if __name__ == "__main__":
    monitor_alerts()
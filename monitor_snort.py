import time
import os
import re
import subprocess
import psutil

# 全局變數來維護 SID 計數器
sid_counter = 1000020

def extract_ip(alert_line):
    """根據 Snort 警報格式提取 IP 地址。"""
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', alert_line)
    if match:
        return match.group(1)
    return None

def clear_list():
    """在開始時清空 whitelist.rules 文件。"""
    with open('/etc/snort/rules/white_list.rules', 'w') as f:
        f.write('')
    with open('/var/log/snort/alert', 'w') as f:
        f.write('')
    for file_name in os.listdir('/var/log/snort'):
        if file_name.startswith('snort.log.'):
            os.remove(os.path.join('/var/log/snort', file_name))

def update_whitelist(triggered_ips):
    """更新 whitelist.rules 文件，將新觸發的 IP 添加到白名單。"""
    global sid_counter
    with open('/etc/snort/rules/white_list.rules', 'a') as f:
        for ip in triggered_ips:
            rule = (f'pass ip {ip} any -> any any (msg:"Allow all traffic from triggered IP"; sid:{sid_counter}; rev:1;)\n')
            f.write(rule)
            print(f'Added rule: {rule.strip()}')
            sid_counter += 1

def stop_snort():
    """Stop the Snort process."""
    for proc in psutil.process_iter(['pid', 'cmdline']):
        if '/etc/snort/snort.conf' in proc.cmdline() and 'gerp' not in proc.cmdline()[0]:
            try:
#                proc.terminate()
                proc.kill()
                proc.wait(timeout=5)  # Wait for termination (adjust timeout if necessary)
                print(f"Stopped Snort process with PID: {proc.pid}")
            except psutil.TimeoutExpired:
                print(f"Timeout expired while terminating Snort process with PID: {proc.pid}")
                            
def reload_snort():
    """Reload Snort with specific configuration and interface."""
    try:
        stop_snort()
        subprocess.run(['sudo', 'snort', '-Q', '--daq', 'nfq', '--daq-var', 'queue=1', '-c', '/etc/snort/snort.conf'], check=True)
        print("Started new Snort process")
    except subprocess.CalledProcessError as e:
        print(f"Error reloading Snort: {e}")

def monitor_alerts():
    alert_file = '/var/log/snort/alert'
    triggered_ips = set()
    last_position = 0

    clear_list()

    while True:
        try:
            with open(alert_file, 'r') as f:
                f.seek(last_position)
                lines = f.readlines()  # Read all lines from last_position onwards
                for line_index, line in enumerate(lines):
                    if "1000010" in line:
                        print(f'Found alert: {line.strip()}')
                        # read two lines
                        if line_index + 2 < len(lines):
                            next_line = lines[line_index + 2]
                            triggered_ip = extract_ip(next_line)
                            if triggered_ip:
                                print(f'Triggered IP: {triggered_ip}')
                                triggered_ips.add(triggered_ip)
                                update_whitelist(triggered_ips)
                                triggered_ips.clear()
                                reload_snort()
                last_position = f.tell()
        except FileNotFoundError:
            print(f"File '{alert_file}' not found.")
        except Exception as e:
            print(f"Error: {e}")

        time.sleep(10)

if __name__ == "__main__":
    try:
        monitor_alerts()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Stopping Snort and exiting.")
        stop_snort()
        clear_list()
    print('Done.')

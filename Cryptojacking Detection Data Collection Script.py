import psutil
import time
import csv
from datetime import datetime
from bcc import BPF
import re

# 已知矿池域名列表
MINING_POOLS = ['xmrpool.eu', 'nanopool.org', 'supportxmr.com']


#sudo apt update
#sudo apt install bpfcc-tools linux-headers-$(uname -r) python3-pip sysdig
#pip3 install psutil bcc

# BCC 程序：跟踪 TCP 连接
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(connections, u32, u64);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 ts = bpf_ktime_get_ns();
    connections.update(&pid, &ts);
    return 0;
}
"""

# 初始化 BCC
b = BPF(text=bpf_text)
connection_counts = {}

# 进程特征
def get_process_features(process):
    try:
        pid = process.pid
        cmdline = ' '.join(process.cmdline())
        # 检查 BCC 连接计数
        conn_count = connection_counts.get(pid, 0)
        # 检查命令行关键字
        contains_stratum = 1 if 'stratum' in cmdline.lower() else 0
        monero_address_pattern = r'\b[48][0-9a-zA-Z]{94}\b'
        contains_wallet = 1 if re.search(monero_address_pattern, cmdline) else 0
        # 检查已知挖矿软件
        mining_software = ['xmrig', 'minerd', 'cpuminer']
        is_mining_software = 1 if process.name().lower() in mining_software else 0
        return {
            'pid': pid,
            'name': process.name(),
            'cmdline': cmdline,
            'cpu_percent': process.cpu_percent(interval=0.1),
            'memory_mb': process.memory_info().rss / 1024 / 1024,
            'connections': conn_count,
            'contains_stratum': contains_stratum,
            'contains_wallet': contains_wallet,
            'is_mining_software': is_mining_software,
            'user': process.username(),
            'uptime': time.time() - process.create_time(),
            'threads': process.num_threads(),
            'nice_value': process.nice(),
            'timestamp': datetime.now().isoformat()
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

# 系统特征
def get_system_features():
    return {
        'total_cpu_percent': psutil.cpu_percent(interval=0.1),
        'total_memory_percent': psutil.virtual_memory().percent,
        'total_net_bytes_sent': psutil.net_io_counters().bytes_sent,
        'total_net_bytes_recv': psutil.net_io_counters().bytes_recv,
        'process_count': len(psutil.pids()),
        'timestamp': datetime.now().isoformat()
    }

# 数据收集主函数
def collect_data(output_file, duration=3600, interval=60):
    start_time = time.time()
    with open(output_file, 'w', newline='') as f:
        fieldnames = ['pid', 'name', 'cmdline', 'cpu_percent', 'memory_mb', 'connections', 
                      'contains_stratum', 'contains_wallet', 'is_mining_software', 'user', 
                      'uptime', 'threads', 'nice_value', 'total_cpu_percent', 
                      'total_memory_percent', 'total_net_bytes_sent', 'total_net_bytes_recv', 
                      'process_count', 'timestamp', 'label']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        while time.time() - start_time < duration:
            # 更新 BCC 连接计数
            for pid, ts in b["connections"].items():
                connection_counts[pid] = connection_counts.get(pid, 0) + 1
            b["connections"].clear()
            
            for proc in psutil.process_iter(['pid', 'name']):
                proc_features = get_process_features(proc)
                if proc_features:
                    sys_features = get_system_features()
                    proc_features.update(sys_features)
                    proc_features['label'] = 'unknown'  # 需手动或自动标记
                    writer.writerow(proc_features)
            time.sleep(interval)

if __name__ == "__main__":
    output_file = "cryptojacking_data.csv"
    collect_data(output_file, duration=3600, interval=60)
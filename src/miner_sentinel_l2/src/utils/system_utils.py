import psutil
import socket
import subprocess
import re
from typing import List, Dict, Optional
import os


class SystemUtils:
    @staticmethod
    def get_process_info(pid: int) -> Optional[psutil.Process]:
        try:
            return psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    @staticmethod
    def get_all_processes() -> List[psutil.Process]:
        return [proc for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info'])]

    @staticmethod
    def get_network_connections(pid: int) -> List[psutil._common.sconn]:
        try:
            proc = psutil.Process(pid)
            return proc.connections()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

    @staticmethod
    def get_process_cmdline(pid: int) -> List[str]:
        try:
            proc = psutil.Process(pid)
            return proc.cmdline()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

    @staticmethod
    def is_known_mining_pool(ip: str, port: int) -> bool:
        """检查是否连接到已知矿池"""
        known_mining_ports = {3333, 4444, 5555, 7777, 8888, 9999, 14444, 3032}
        known_mining_domains = {'.stratum.', '.pool.', '.mine.', '.mining.'}

        # 检查端口
        if port in known_mining_ports:
            return True

        # 尝试解析域名（如果有）
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if any(domain in hostname for domain in known_mining_domains):
                return True
        except (socket.herror, socket.gaierror):
            pass

        return False

    @staticmethod
    def get_system_uptime() -> float:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        return uptime_seconds

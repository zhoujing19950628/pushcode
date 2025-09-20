import psutil
import socket
from typing import Dict, List
from ..utils.system_utils import SystemUtils


class NetworkMiningDetector:
    def __init__(self):
        self.utils = SystemUtils()
        self.known_mining_ports = {3333, 4444, 5555, 7777, 8888, 9999, 14444, 3032}

    def analyze_process(self, pid: int) -> Dict[str, float]:
        """分析进程的网络连接"""
        connections = self.utils.get_network_connections(pid)
        score = 0.0
        evidences = []

        mining_connections = []
        for conn in connections:
            if hasattr(conn, 'raddr') and conn.raddr:
                ip, port = conn.raddr

                # 检查已知矿池端口
                if port in self.known_mining_ports:
                    mining_connections.append((ip, port))
                    score += 0.6
                    evidences.append(f"连接到已知矿池端口: {ip}:{port}")

                # # 检查域名特征
                # elif self.utils.is_known_mining_pool(ip, port):
                #     mining_connections.append((ip, port))
                #     score += 0.4
                #     evidences.append(f"连接到疑似矿池: {ip}:{port}")

        # 检查连接数量和小数据包模式
        if len(connections) > 5:
            # 分析数据包模式（这里简化处理）
            score += 0.2
            evidences.append("多个网络连接")

        return {
            'network_score': min(score, 1.0),
            'network_confidence': score * 0.9,
            'mining_connections': mining_connections,
            'evidences': evidences
        }

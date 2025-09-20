import psutil
import re
from typing import Dict, List
from ..utils.system_utils import SystemUtils


class ProcessBehaviorDetector:
    def __init__(self):
        self.utils = SystemUtils()
        self.mining_keywords = {
            'miner', 'xmrig', 'ccminer', 'ethminer', 'cpuminer',
            'stratum', 'pool', 'mine', 'rig', 'crypto', 'coin'
        }
        self.suspicious_patterns = [
            r'--pool=', r'--url=', r'--user=', r'--pass=',
            r'stratum\+tcp://', r'stratum\+ssl://'
        ]

    def analyze_process(self, pid: int) -> Dict[str, float]:
        """分析进程行为特征"""
        score = 0.0
        evidences = []

        # 获取进程信息
        process = self.utils.get_process_info(pid)
        if not process:
            return {'process_score': 0, 'evidences': []}

        # 检查进程名
        process_name = process.name().lower()
        if any(keyword in process_name for keyword in self.mining_keywords):
            score += 0.5
            evidences.append(f"可疑进程名: {process_name}")

        # 检查命令行参数
        cmdline = ' '.join(self.utils.get_process_cmdline(pid)).lower()
        if cmdline:
            # 关键词匹配
            keyword_matches = [kw for kw in self.mining_keywords if kw in cmdline]
            if keyword_matches:
                score += 0.4
                evidences.append(f"命令行包含挖矿关键词: {', '.join(keyword_matches)}")

            # 模式匹配
            pattern_matches = []
            for pattern in self.suspicious_patterns:
                if re.search(pattern, cmdline):
                    pattern_matches.append(pattern)
            if pattern_matches:
                score += 0.3
                evidences.append(f"命令行包含可疑模式: {', '.join(pattern_matches)}")

        # 检查运行权限和用户
        try:
            if process.username() in ['root', 'system']:
                score += 0.2
                evidences.append("以高权限运行")
        except:
            pass

        # 检查是否有GUI
        try:
            if not process.windows():
                score += 0.1
                evidences.append("无GUI界面")
        except:
            pass

        return {
            'process_score': min(score, 1.0),
            'process_confidence': score * 0.85,
            'evidences': evidences
        }

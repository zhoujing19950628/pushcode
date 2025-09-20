import psutil
import time
from typing import Dict, List
from collections import deque
from ..models.detection_result import DetectionResult


class CPUMiningDetector:
    def __init__(self, history_size: int = 10):
        self.history_size = history_size
        self.process_history = {}
        self.mining_keywords = {'miner', 'xmrig', 'ccminer', 'ethminer', 'cpuminer'}

    def analyze_process(self, process: psutil.Process) -> Dict[str, float]:
        """分析单个进程的CPU模式"""
        pid = process.pid
        current_time = time.time()

        # 初始化历史记录
        if pid not in self.process_history:
            self.process_history[pid] = {
                'cpu_samples': deque(maxlen=self.history_size),
                'timestamps': deque(maxlen=self.history_size),
                'start_time': current_time
            }

        history = self.process_history[pid]

        # 记录当前CPU使用率
        cpu_usage = process.cpu_percent(interval=0.1)
        history['cpu_samples'].append(cpu_usage)
        history['timestamps'].append(current_time)

        # 计算特征
        features = {
            'cpu_usage_current': cpu_usage,
            'cpu_usage_avg': self._calculate_avg(history['cpu_samples']),
            'cpu_usage_std': self._calculate_std(history['cpu_samples']),
            'cpu_usage_max': max(history['cpu_samples']) if history['cpu_samples'] else 0,
            'process_uptime': current_time - history['start_time']
        }

        return self._calculate_score(features, process)

    def _calculate_avg(self, samples: deque) -> float:
        return sum(samples) / len(samples) if samples else 0

    def _calculate_std(self, samples: deque) -> float:
        if len(samples) < 2:
            return 0
        mean = self._calculate_avg(samples)
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)
        return variance ** 0.5

    def _calculate_score(self, features: Dict, process: psutil.Process) -> Dict[str, float]:
        """计算CPU相关得分"""
        score = 0.0
        evidences = []

        # 高CPU使用率
        if features['cpu_usage_avg'] > 70:
            score += 0.3
            evidences.append(f"高CPU使用率: {features['cpu_usage_avg']:.1f}%")

        # 稳定的CPU使用（挖矿特征）
        if features['cpu_usage_std'] < 5 and features['cpu_usage_avg'] > 30:
            score += 0.2
            evidences.append(f"稳定的CPU使用模式")

        # 长时间运行
        if features['process_uptime'] > 3600:  # 1小时
            score += 0.1
            evidences.append(f"长时间运行: {features['process_uptime'] / 3600:.1f}小时")

        # 进程名包含挖矿关键词
        process_name = process.name().lower()
        if any(keyword in process_name for keyword in self.mining_keywords):
            score += 0.4
            evidences.append(f"进程名包含挖矿关键词: {process_name}")

        return {
            'cpu_score': min(score, 1.0),
            'cpu_confidence': score * 0.8,  # 置信度调整
            'evidences': evidences
        }

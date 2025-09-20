import psutil
from typing import Dict


class MemoryMiningDetector:
    def __init__(self):
        self.memory_threshold = 0.9  # 90%内存使用率

    def analyze_system_memory(self) -> Dict[str, float]:
        """分析系统内存使用情况"""
        memory = psutil.virtual_memory()
        score = 0.0
        evidences = []

        memory_usage = memory.percent / 100

        if memory_usage > self.memory_threshold:
            score = 0.3
            evidences.append(f"高内存使用率: {memory.percent}%")

        return {
            'memory_score': score,
            'memory_confidence': score * 0.6,  # 内存指标置信度较低
            'memory_usage': memory_usage,
            'evidences': evidences
        }

    def analyze_process_memory(self, process: psutil.Process) -> Dict[str, float]:
        """分析单个进程的内存使用"""
        try:
            memory_info = process.memory_info()
            memory_usage = memory_info.rss / (1024 * 1024)  # MB

            score = 0.0
            evidences = []

            # 如果进程使用大量内存但CPU不高，可能可疑
            if memory_usage > 500:  # 500MB
                score = 0.2
                evidences.append(f"高内存使用: {memory_usage:.1f}MB")

            return {
                'process_memory_score': score,
                'process_memory_confidence': score * 0.5,
                'evidences': evidences
            }
        except:
            return {'process_memory_score': 0, 'evidences': []}

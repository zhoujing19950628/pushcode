from typing import Dict, List, Optional
from .cpu_detector import CPUMiningDetector
from .network_detector import NetworkMiningDetector
from .process_detector import ProcessBehaviorDetector
from .memory_detector import MemoryMiningDetector
from ..models.detection_result import DetectionResult
from ..utils.whitelist_manager import WhitelistManager
import psutil


class ComprehensiveMiningDetector:
    def __init__(self, whitelist_manager: Optional[WhitelistManager] = None):
        self.cpu_detector = CPUMiningDetector()
        self.network_detector = NetworkMiningDetector()
        self.process_detector = ProcessBehaviorDetector()
        self.memory_detector = MemoryMiningDetector()
        self.whitelist_manager = whitelist_manager

        # 检测器权重配置
        self.weights = {
            'cpu': 0.35,
            'network': 0.30,
            'process': 0.25,
            'memory': 0.10,
        }

    def analyze_process(self, pid: int) -> Optional[DetectionResult]:
        """综合分析单个进程，如果进程在白名单中则返回None"""
        try:
            process = psutil.Process(pid)

            # 检查白名单
            if self.whitelist_manager and self.whitelist_manager.is_whitelisted(process):
                return None

            result = DetectionResult(process_id=pid, process_name=process.name())

            # 各维度检测
            cpu_result = self.cpu_detector.analyze_process(process)
            network_result = self.network_detector.analyze_process(pid)
            process_result = self.process_detector.analyze_process(pid)
            memory_result = self.memory_detector.analyze_process_memory(process)

            # 计算总分
            total_score = (
                    cpu_result['cpu_score'] * self.weights['cpu'] +
                    network_result['network_score'] * self.weights['network'] +
                    process_result['process_score'] * self.weights['process'] +
                    memory_result['process_memory_score'] * self.weights['memory']
            )

            # 计算置信度
            confidence = (
                    cpu_result['cpu_confidence'] * self.weights['cpu'] +
                    network_result['network_confidence'] * self.weights['network'] +
                    process_result['process_confidence'] * self.weights['process'] +
                    memory_result['process_memory_confidence'] * self.weights['memory']
            )

            # 收集证据
            all_evidences = []
            all_evidences.extend(cpu_result.get('evidences', []))
            all_evidences.extend(network_result.get('evidences', []))
            all_evidences.extend(process_result.get('evidences', []))
            all_evidences.extend(memory_result.get('evidences', []))

            # 设置结果
            result.total_score = total_score
            result.confidence = confidence
            result.details = {
                'cpu_score': cpu_result['cpu_score'],
                'network_score': network_result['network_score'],
                'process_score': process_result['process_score'],
                'memory_score': memory_result['process_memory_score']
            }
            result.evidences = all_evidences

            # 确定状态
            if total_score >= 0.7:
                result.status = "CONFIRMED"
            elif total_score >= 0.4:
                result.status = "SUSPICIOUS"
            else:
                result.status = "NORMAL"

            return result

        except Exception as e:
            # 对于无法访问的进程，创建一个简单的结果
            result = DetectionResult(process_id=pid, process_name="unknown")
            result.evidences.append(f"进程访问失败: {str(e)}")
            return result

import time
from typing import Dict, Optional
from .utils import read_key_value_file, read_memory_pressure_indicators


class VmStatMetricsCalculator:
    """计算/proc/vmstat指标的每秒变化率"""

    def __init__(self):
        self.previous_values: Optional[Dict[str, int]] = None
        self.previous_timestamp: Optional[float] = None

    def calculate_rates(self) -> Dict[str, float]:
        """计算各项指标的每秒变化率"""
        current_time = time.time()
        current_values = read_key_value_file("/proc/vmstat")
        rates = {}

        if self.previous_values is not None and self.previous_timestamp is not None:
            time_delta = max(current_time - self.previous_timestamp, 1e-6)

            metrics_to_track = ["pgfault", "pgmajfault", "pswpin", "pswpout"]
            for metric in metrics_to_track:
                if metric in current_values and metric in self.previous_values:
                    rate = (current_values[metric] - self.previous_values[metric]) / time_delta
                    rates[f"{metric}_per_sec"] = rate

        self.previous_values = current_values
        self.previous_timestamp = current_time

        return rates


class MemoryMetricsCollector:
    """内存指标采集器"""

    def __init__(self):
        self.vmstat_calculator = VmStatMetricsCalculator()
        self.previous_fault_counts = None
        self.is_warmup_complete = False
        # 执行一次初始采集完成预热
        self._warmup()

    def _warmup(self):
        """执行初始采集完成系统预热"""
        self.collect_memory_usage()
        self.vmstat_calculator.calculate_rates()
        self.is_warmup_complete = True

    def collect_memory_usage(self) -> float:
        """采集内存使用率"""
        mem_info = read_key_value_file("/proc/meminfo")
        total_memory = mem_info.get("MemTotal", 0)
        available_memory = mem_info.get("MemAvailable", 0)

        if total_memory <= 0:
            return 0.0

        usage_ratio = 1.0 - (available_memory / total_memory)
        return max(0.0, min(1.0, usage_ratio))

    def estimate_cache_hit_ratio(self) -> Optional[float]:
        """估算页面缓存命中率"""
        current_stats = read_key_value_file("/proc/vmstat")
        current_faults = (
            current_stats.get("pgfault", 0),
            current_stats.get("pgmajfault", 0)
        )

        hit_ratio = None

        if self.previous_fault_counts is not None:
            previous_minor, previous_major = self.previous_fault_counts
            current_minor, current_major = current_faults

            delta_minor = current_minor - previous_minor
            delta_major = current_major - previous_major

            if delta_minor > 0:
                miss_ratio = max(0.0, min(1.0, delta_major / delta_minor))
                hit_ratio = 1.0 - miss_ratio

        self.previous_fault_counts = current_faults
        return hit_ratio

    def collect_pressure_indicators(self) -> Dict[str, float]:
        """采集内存压力指标（PSI）"""
        return read_memory_pressure_indicators()

    def collect_all_metrics(self) -> Dict[str, float]:
        """采集所有内存相关指标"""
        metrics = {}

        metrics["memory_usage"] = self.collect_memory_usage()

        cache_hit_ratio = self.estimate_cache_hit_ratio()
        if cache_hit_ratio is not None:
            metrics["cache_hit_ratio"] = cache_hit_ratio

        metrics.update(self.collect_pressure_indicators())
        metrics.update(self.vmstat_calculator.calculate_rates())

        return metrics

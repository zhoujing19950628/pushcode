import json
import time
from pathlib import Path
from typing import Dict

from .collector import MemoryMetricsCollector
from .analyzer import MemoryPressureAnalyzer
from .window import TimeSlidingWindow


class MemoryJudge:
    """挖矿行为检测器"""

    def __init__(self, config: Dict, project_root: Path):
        self.config = config
        self.project_root = project_root
        self.metrics_collector = MemoryMetricsCollector()
        self.analyzer = MemoryPressureAnalyzer(config)

        # 初始化滑动窗口
        self.monitoring_metrics = [
            "memory_usage", "cache_hit_ratio", "some_avg10", "full_avg10",
            "pgmajfault_per_sec", "pswpin_per_sec", "pswpout_per_sec"
        ]
        self.metric_windows = {
            metric: TimeSlidingWindow(config.get("time_window_seconds", 60))
            for metric in self.monitoring_metrics
        }

        self.events_log_path = project_root / "runtime" / "logs" / "events.jsonl"
        self.last_alert_time = 0.0
        self.consecutive_healthy_samples = 0

    def _check_recovery_conditions(self, raw_metrics: Dict[str, float], recovery_config: Dict) -> bool:
        """检查恢复条件"""
        memory_usage = raw_metrics.get("memory_usage", 1.0)
        cache_hit_ratio = raw_metrics.get("cache_hit_ratio", 0.0)
        major_faults = raw_metrics.get("pgmajfault_per_sec", float('inf'))
        swap_in = raw_metrics.get("pswpin_per_sec", 0.0)
        swap_out = raw_metrics.get("pswpout_per_sec", 0.0)
        total_swap = swap_in + swap_out

        return (
                memory_usage < recovery_config.get("max_memory_usage", 0.85) and
                cache_hit_ratio > recovery_config.get("min_cache_hit_ratio", 0.95) and
                major_faults < recovery_config.get("max_major_faults_per_sec", 5.0) and
                total_swap < recovery_config.get("max_swap_activity_per_sec", 100.0)
        )

    def _create_heartbeat_message(self, timestamp: float, status: str, total_score: int,
                                  category_count: int, metrics: Dict[str, float],
                                  component_scores: Dict[str, int]) -> Dict:
        """创建心跳消息"""
        return {
            "timestamp": int(timestamp),
            "status": status,
            "total_score": total_score,
            "category_count": category_count,
            "memory_usage": round(metrics.get("memory_usage", 0.0), 3),
            "cache_hit_ratio": round(metrics.get("cache_hit_ratio", 0.0), 3) if "cache_hit_ratio" in metrics else None,
            "some_pressure": round(metrics.get("some_avg10", 0.0), 3),
            "full_pressure": round(metrics.get("full_avg10", 0.0), 3),
            "major_faults_per_sec": round(metrics.get("pgmajfault_per_sec", 0.0), 3),
            "swap_activity_per_sec": round(
                metrics.get("pswpin_per_sec", 0.0) + metrics.get("pswpout_per_sec", 0.0), 3
            ),
            "component_scores": component_scores
        }

    def _log_event(self, timestamp: float, status: str, total_score: int,
                   category_count: int, heartbeat: Dict):
        """记录事件到日志文件"""
        event = {
            "timestamp": int(timestamp),
            "level": status,
            "score": total_score,
            "categories": category_count,
            "details": heartbeat
        }

        try:
            with open(self.events_log_path, "a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(event, ensure_ascii=False) + "\n")
        except IOError as e:
            print(f"无法写入事件日志: {e}", flush=True)

    def run_detection_cycle(self) -> Dict:
        """执行一次完整的检测周期"""
        cycle_start = time.time()

        # 采集原始指标
        raw_metrics = self.metrics_collector.collect_all_metrics()
        current_time = time.time()

        # 更新滑动窗口
        for metric_name, value in raw_metrics.items():
            if metric_name in self.metric_windows:
                self.metric_windows[metric_name].add_value(value, current_time)

        # 计算窗口聚合值
        windowed_metrics = {}
        for metric_name, window in self.metric_windows.items():
            if metric_name in ["pgmajfault_per_sec", "pswpin_per_sec", "pswpout_per_sec"]:
                windowed_metrics[metric_name] = window.calculate_median()
            else:
                windowed_metrics[metric_name] = window.calculate_mean()

        # 分析与评分
        total_score, component_scores, category_count = self.analyzer.calculate_total_score(windowed_metrics)
        status = self.analyzer.determine_status(total_score, category_count)

        return {
            "raw_metrics": raw_metrics,
            "windowed_metrics": windowed_metrics,
            "total_score": total_score,
            "component_scores": component_scores,
            "category_count": category_count,
            "status": status,
            "cycle_start": cycle_start,
            "current_time": current_time
        }

    def check_recovery_and_reset(self, raw_metrics: Dict[str, float], sampling_interval: float,
                                 recovery_config: Dict) -> bool:
        """检查恢复条件并在满足时重置"""
        is_healthy = self._check_recovery_conditions(raw_metrics, recovery_config)

        if is_healthy:
            self.consecutive_healthy_samples += 1
        else:
            self.consecutive_healthy_samples = 0

        # 如果连续健康样本达到要求，重置系统
        required_healthy_samples = max(1, int(recovery_config.get("recovery_time_seconds", 20) / sampling_interval))
        if self.consecutive_healthy_samples >= required_healthy_samples:
            for window in self.metric_windows.values():
                window.clear()
            self.consecutive_healthy_samples = 0
            return True

        return False

    def should_log_event(self, status: str, current_time: float, cooldown_period: float) -> bool:
        """判断是否需要记录事件"""
        return (status in ["WARNING", "CRITICAL"] and
                (current_time - self.last_alert_time >= cooldown_period))

    def update_alert_time(self, current_time: float):
        """更新最后告警时间"""
        self.last_alert_time = current_time

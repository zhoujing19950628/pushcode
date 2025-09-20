from typing import Dict, Tuple


class MemoryPressureAnalyzer:
    """内存压力分析器"""

    def __init__(self, config: Dict):
        self.config = config

    def evaluate_memory_usage(self, usage_ratio: float) -> int:
        """评估内存使用率得分"""
        rules = self.config.get("memory_usage", {})
        if not rules.get("enabled", True):
            return 0

        if usage_ratio >= rules.get("critical_threshold", 0.95):
            return rules.get("critical_score", 25)
        elif usage_ratio >= rules.get("warning_threshold", 0.90):
            return rules.get("warning_score", 15)
        return 0

    def evaluate_cache_performance(self, hit_ratio: float) -> int:
        """评估缓存性能得分"""
        rules = self.config.get("cache_performance", {})
        if not rules.get("enabled", True):
            return 0

        if hit_ratio < rules.get("critical_threshold", 0.80):
            return rules.get("critical_score", 30)
        elif hit_ratio < rules.get("warning_threshold", 0.90):
            return rules.get("warning_score", 15)
        return 0

    def evaluate_page_faults(self, major_faults_per_sec: float) -> int:
        """评估缺页异常得分"""
        rules = self.config.get("page_faults", {})
        if not rules.get("enabled", True):
            return 0

        if major_faults_per_sec >= rules.get("critical_threshold", 100):
            return rules.get("critical_score", 20)
        elif major_faults_per_sec >= rules.get("warning_threshold", 20):
            return rules.get("warning_score", 10)
        return 0

    def evaluate_memory_pressure(self, some_pressure: float, full_pressure: float) -> int:
        """评估内存压力得分"""
        rules = self.config.get("memory_pressure", {})
        if not rules.get("enabled", True):
            return 0

        score = 0
        if some_pressure >= rules.get("some_warning_threshold", 5.0):
            score += rules.get("some_weight", 10)
        if full_pressure >= rules.get("full_warning_threshold", 1.0):
            score += rules.get("full_weight", 15)

        return score

    def evaluate_swap_activity(self, swap_in_per_sec: float, swap_out_per_sec: float) -> int:
        """评估交换活动得分"""
        rules = self.config.get("swap_activity", {})
        if not rules.get("enabled", True):
            return 0

        total_swap = swap_in_per_sec + swap_out_per_sec

        if total_swap >= rules.get("critical_threshold", 1000):
            return rules.get("critical_score", 10)
        elif total_swap >= rules.get("warning_threshold", 300):
            return rules.get("warning_score", 5)
        return 0

    def calculate_total_score(self, metrics: Dict[str, float]) -> Tuple[int, Dict[str, int], int]:
        """计算总得分和各项得分"""
        total_score = 0
        component_scores = {}
        triggered_categories = 0

        # 评估各项指标
        if "memory_usage" in metrics:
            score = self.evaluate_memory_usage(metrics["memory_usage"])
            if score > 0:
                component_scores["memory_usage"] = score
                total_score += score
                triggered_categories += 1

        if "cache_hit_ratio" in metrics:
            score = self.evaluate_cache_performance(metrics["cache_hit_ratio"])
            if score > 0:
                component_scores["cache_performance"] = score
                total_score += score
                triggered_categories += 1

        if "pgmajfault_per_sec" in metrics:
            score = self.evaluate_page_faults(metrics["pgmajfault_per_sec"])
            if score > 0:
                component_scores["page_faults"] = score
                total_score += score
                triggered_categories += 1

        if "some_avg10" in metrics and "full_avg10" in metrics:
            score = self.evaluate_memory_pressure(metrics["some_avg10"], metrics["full_avg10"])
            if score > 0:
                component_scores["memory_pressure"] = score
                total_score += score
                triggered_categories += 1

        swap_score = self.evaluate_swap_activity(
            metrics.get("pswpin_per_sec", 0),
            metrics.get("pswpout_per_sec", 0)
        )
        if swap_score > 0:
            component_scores["swap_activity"] = swap_score
            total_score += swap_score
            triggered_categories += 1

        return total_score, component_scores, triggered_categories

    def determine_status(self, total_score: int, triggered_categories: int) -> str:
        """根据得分确定状态"""
        decision_rules = self.config.get("decision", {})

        if (total_score >= decision_rules.get("critical_threshold", 60) and
                triggered_categories >= decision_rules.get("min_categories_for_critical", 2)):
            return "CRITICAL"

        if total_score >= decision_rules.get("warning_threshold", 40):
            return "WARNING"

        return "NORMAL"

import time
from typing import Dict, Optional


def _read_first_line(path: str) -> Optional[str]:
    try:
        with open(path, "r") as f:
            return f.readline().strip()
    except Exception:
        return None


def _read_file(path: str) -> Optional[str]:
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception:
        return None


def read_key_value_file(path: str) -> Dict[str, int]:
    """保留你原 utils 的功能：这里内联一个最小实现，若你已有 utils 版本就用原来的。"""
    data: Dict[str, int] = {}
    txt = _read_file(path)
    if not txt:
        return data
    for line in txt.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            data[parts[0]] = int(parts[1])
    return data


def read_memory_pressure_indicators() -> Dict[str, float]:
    """从 /proc/pressure/memory 读取 some/full 的 avg10，键名与现有 analyzer 对齐。"""
    out: Dict[str, float] = {}
    txt = _read_file("/proc/pressure/memory")
    if not txt:
        return out
    for line in txt.splitlines():
        if line.startswith("some"):
            # 格式: some avg10=1.23 avg60=... avg300=... total=...
            try:
                kvs = dict(kv.split("=", 1) for kv in line.split()[1:])
                out["some_avg10"] = float(kvs.get("avg10", "0"))
            except Exception:
                pass
        elif line.startswith("full"):
            try:
                kvs = dict(kv.split("=", 1) for kv in line.split()[1:])
                out["full_avg10"] = float(kvs.get("avg10", "0"))
            except Exception:
                pass
    return out


class VmStatMetricsCalculator:
    """计算 /proc/vmstat 指标的每秒变化率"""

    def __init__(self):
        self.previous_values: Optional[Dict[str, int]] = None
        self.previous_timestamp: Optional[float] = None

    def calculate_rates(self) -> Dict[str, float]:
        current_time = time.time()
        current_values = read_key_value_file("/proc/vmstat")
        rates: Dict[str, float] = {}

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


class CPUUtilCalculator:
    """基于 /proc/stat 计算全局 CPU 利用率（0~1）"""

    def __init__(self):
        self.prev_total: Optional[int] = None
        self.prev_idle_all: Optional[int] = None

    def _read_cpu_times(self) -> Optional[Dict[str, int]]:
        line = _read_first_line("/proc/stat")
        if not line:
            return None
        parts = line.split()
        if not parts or parts[0] != "cpu":
            return None
        # 字段顺序：user nice system idle iowait irq softirq steal guest guest_nice
        nums = [int(x) for x in parts[1:]]
        # 兼容长度不足的内核
        while len(nums) < 8:
            nums.append(0)
        user, nice, system, idle, iowait, irq, softirq, steal = nums[:8]
        idle_all = idle + iowait
        non_idle = user + nice + system + irq + softirq + steal
        total = idle_all + non_idle
        return {"total": total, "idle_all": idle_all}

    def calculate_utilization(self) -> Optional[float]:
        t = self._read_cpu_times()
        if t is None:
            return None
        if self.prev_total is None or self.prev_idle_all is None:
            self.prev_total, self.prev_idle_all = t["total"], t["idle_all"]
            return None  # 首次无 delta
        delta_total = t["total"] - self.prev_total
        delta_idle = t["idle_all"] - self.prev_idle_all
        self.prev_total, self.prev_idle_all = t["total"], t["idle_all"]
        if delta_total <= 0:
            return None
        util = 1.0 - (delta_idle / float(delta_total))
        # 裁剪到 [0,1]
        return max(0.0, min(1.0, util))


class MemoryMetricsCollector:
    """内存 + 系统压力指标采集器（新增 CPU PSI & CPU 利用率）"""

    def __init__(self):
        self.vmstat_calculator = VmStatMetricsCalculator()
        self.cpu_util_calculator = CPUUtilCalculator()
        self.previous_fault_counts = None
        self.is_warmup_complete = False
        self._warmup()

    def _warmup(self):
        """执行初始采集完成预热"""
        self.collect_memory_usage()
        self.vmstat_calculator.calculate_rates()
        self.cpu_util_calculator.calculate_utilization()  # 预热一次，下一次才有 delta
        self.is_warmup_complete = True

    # ---------- 内存相关（原有） ----------

    def collect_memory_usage(self) -> float:
        mem_info = read_key_value_file("/proc/meminfo")
        total_memory = mem_info.get("MemTotal", 0)
        available_memory = mem_info.get("MemAvailable", 0)
        if total_memory <= 0:
            return 0.0
        usage_ratio = 1.0 - (available_memory / total_memory)
        return max(0.0, min(1.0, usage_ratio))

    def estimate_cache_hit_ratio(self) -> Optional[float]:
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
                miss_ratio = max(0.0, min(1.0, delta_major / max(1.0, float(delta_minor))))
                hit_ratio = 1.0 - miss_ratio
        self.previous_fault_counts = current_faults
        return hit_ratio

    def collect_pressure_indicators(self) -> Dict[str, float]:
        """采集内存压力指标（PSI）"""
        return read_memory_pressure_indicators()

    # ---------- 新增的 CPU 指标 ----------

    def collect_cpu_pressure(self) -> Dict[str, float]:
        """采集 CPU PSI（/proc/pressure/cpu 的 some.avg10）"""
        out: Dict[str, float] = {}
        txt = _read_file("/proc/pressure/cpu")
        if not txt:
            return out
        for line in txt.splitlines():
            if line.startswith("some"):
                try:
                    kvs = dict(kv.split("=", 1) for kv in line.split()[1:])
                    out["cpu_some_avg10"] = float(kvs.get("avg10", "0"))
                except Exception:
                    pass
                break
        return out

    def collect_cpu_utilization(self) -> Optional[float]:
        """采集全局 CPU 利用率（0~1）"""
        return self.cpu_util_calculator.calculate_utilization()

    # ---------- 汇总 ----------

    def collect_all_metrics(self) -> Dict[str, float]:
        metrics: Dict[str, float] = {}

        # 内存使用率
        metrics["memory_usage"] = self.collect_memory_usage()

        # 缓存命中率（可为空）
        cache_hit_ratio = self.estimate_cache_hit_ratio()
        if cache_hit_ratio is not None:
            metrics["cache_hit_ratio"] = cache_hit_ratio

        # 内存 PSI、vmstat 速率
        metrics.update(self.collect_pressure_indicators())
        metrics.update(self.vmstat_calculator.calculate_rates())

        # CPU PSI
        metrics.update(self.collect_cpu_pressure())

        # CPU 利用率（可为空）
        cpu_util = self.collect_cpu_utilization()
        if cpu_util is not None:
            metrics["cpu_utilization"] = cpu_util

        return metrics

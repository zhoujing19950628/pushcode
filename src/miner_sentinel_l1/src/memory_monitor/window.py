from collections import deque
from typing import Deque, Tuple, Optional
import time
import math

class TimeSlidingWindow:
    """基于时间滑动的窗口，存储 (timestamp, value) 对"""

    def __init__(self, window_seconds: int):
        self.window_seconds = int(window_seconds)
        self.data_queue: Deque[Tuple[float, float]] = deque()

    # ---------- 写入 ----------

    def add_value(self, value: Optional[float], timestamp: Optional[float] = None):
        """添加新值到窗口；忽略 None/NaN/Inf"""
        if value is None:
            return
        try:
            v = float(value)
        except (TypeError, ValueError):
            return
        if not math.isfinite(v):
            return

        if timestamp is None:
            timestamp = time.time()
        self.data_queue.append((float(timestamp), v))
        self._trim_old_data(timestamp)

    def _trim_old_data(self, current_time: float):
        """移除过期的数据"""
        cutoff_time = current_time - self.window_seconds
        dq = self.data_queue
        while dq and dq[0][0] < cutoff_time:
            dq.popleft()

    def clear(self):
        """清空窗口数据"""
        self.data_queue.clear()

    # ---------- 读出（聚合） ----------

    def calculate_mean(self) -> float:
        """计算窗口内值的平均值"""
        if not self.data_queue:
            return 0.0
        return sum(v for _, v in self.data_queue) / len(self.data_queue)

    def calculate_median(self) -> float:
        """计算窗口内值的中位数"""
        if not self.data_queue:
            return 0.0
        values = sorted(v for _, v in self.data_queue)
        n = len(values)
        mid = n // 2
        if n % 2 == 1:
            return values[mid]
        return (values[mid - 1] + values[mid]) / 2.0

    # --- 新增：截尾均值（对尖峰更鲁棒，例如 PSI/CPU 利用率） ---
    def calculate_trimmed_mean(self, lower: float = 0.1, upper: float = 0.1) -> float:
        """
        计算截尾均值：按分位剔除两端，默认各砍 10%。
        lower/upper 取值范围 [0, 0.49]，总截尾比例 < 1 才有意义。
        """
        if not self.data_queue:
            return 0.0
        values = sorted(v for _, v in self.data_queue)
        n = len(values)
        lower = max(0.0, min(0.49, float(lower)))
        upper = max(0.0, min(0.49, float(upper)))
        l = int(n * lower)
        r = n - int(n * upper)
        if r <= l:
            # 数据太少或截尾比例过大，退化为普通均值
            return sum(values) / n
        trimmed = values[l:r]
        return sum(trimmed) / len(trimmed)

    # --- 新增：任意分位数（0~100） ---
    def calculate_percentile(self, q: float) -> float:
        """线性插值的近似分位数；q 取值 0~100"""
        if not self.data_queue:
            return 0.0
        q = max(0.0, min(100.0, float(q)))
        values = sorted(v for _, v in self.data_queue)
        if len(values) == 1:
            return values[0]
        pos = (len(values) - 1) * (q / 100.0)
        lo = int(math.floor(pos))
        hi = int(math.ceil(pos))
        if lo == hi:
            return values[lo]
        frac = pos - lo
        return values[lo] * (1.0 - frac) + values[hi] * frac

    # --- 新增：便捷统计 ---
    def max(self) -> float:
        return max((v for _, v in self.data_queue), default=0.0)

    def min(self) -> float:
        return min((v for _, v in self.data_queue), default=0.0)

    def last(self) -> float:
        return self.data_queue[-1][1] if self.data_queue else 0.0

    def count(self) -> int:
        return len(self.data_queue)

    def span_seconds(self) -> float:
        """窗口内覆盖的时间跨度（秒）"""
        if len(self.data_queue) < 2:
            return 0.0
        return self.data_queue[-1][0] - self.data_queue[0][0]

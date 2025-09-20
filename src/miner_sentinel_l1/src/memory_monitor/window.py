from collections import deque
from typing import Deque, Tuple, Optional
import time


class TimeSlidingWindow:
    """基于时间滑动的窗口，存储(timestamp, value)对"""

    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.data_queue: Deque[Tuple[float, float]] = deque()

    def add_value(self, value: float, timestamp: Optional[float] = None):
        """添加新值到窗口"""
        if timestamp is None:
            timestamp = time.time()
        self.data_queue.append((timestamp, value))
        self._trim_old_data(timestamp)

    def _trim_old_data(self, current_time: float):
        """移除过期的数据"""
        cutoff_time = current_time - self.window_seconds
        while self.data_queue and self.data_queue[0][0] < cutoff_time:
            self.data_queue.popleft()

    def calculate_mean(self) -> float:
        """计算窗口内值的平均值"""
        if not self.data_queue:
            return 0.0
        return sum(value for _, value in self.data_queue) / len(self.data_queue)

    def calculate_median(self) -> float:
        """计算窗口内值的中位数"""
        if not self.data_queue:
            return 0.0
        values = sorted(value for _, value in self.data_queue)
        mid_index = len(values) // 2
        if len(values) % 2 == 1:
            return values[mid_index]
        return (values[mid_index - 1] + values[mid_index]) / 2

    def clear(self):
        """清空窗口数据"""
        self.data_queue.clear()

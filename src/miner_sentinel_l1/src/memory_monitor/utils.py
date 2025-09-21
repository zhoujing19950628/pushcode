import os
from typing import Dict


def read_key_value_file(file_path: str) -> Dict[str, int]:
    """读取/proc下的键值对文件（如meminfo, vmstat）"""
    result = {}
    if not os.path.exists(file_path):
        return result

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                parts = line.split()
                key = parts[0].rstrip(':')

                if len(parts) >= 2 and parts[1].lstrip('-').isdigit():
                    result[key] = int(parts[1])
    except (IOError, PermissionError):
        pass

    return result


def read_memory_pressure_indicators() -> Dict[str, float]:
    """读取/proc/pressure/memory中的PSI指标"""
    result = {"some_avg10": 0.0, "full_avg10": 0.0}
    pressure_file = "/proc/pressure/memory"

    if not os.path.exists(pressure_file):
        return result

    try:
        with open(pressure_file, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                parts = line.split()
                pressure_type = parts[0]  # "some" or "full"

                # 解析指标值
                for part in parts[1:]:
                    if '=' in part:
                        metric_name, metric_value = part.split('=', 1)
                        if metric_name == "avg10":
                            try:
                                result_key = f"{pressure_type}_avg10"
                                result[result_key] = float(metric_value)
                            except ValueError:
                                continue
    except (IOError, PermissionError):
        pass

    return result


def read_cpu_pressure_indicators() -> Dict[str, float]:
    """读取 /proc/pressure/cpu 中的 PSI 指标（只需要 some.avg10）"""
    result = {"cpu_some_avg10": 0.0}
    pressure_file = "/proc/pressure/cpu"

    if not os.path.exists(pressure_file):
        return result

    try:
        with open(pressure_file, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                # 形如: "some avg10=2.13 avg60=1.54 avg300=0.89 total=12345678"
                if line.startswith("some"):
                    for part in line.split()[1:]:
                        if part.startswith("avg10="):
                            val = part.split("=", 1)[1]
                            try:
                                result["cpu_some_avg10"] = float(val)
                            except ValueError:
                                pass
                    break
    except (IOError, PermissionError):
        pass

    return result

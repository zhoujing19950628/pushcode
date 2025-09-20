#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import time
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import yaml
import psutil

# -----------------------------
# 路径推导
# 本文件：.../kylin-ai-cryptojacking-detect/src/miner_sentinel_l1/src/main.py
# 工程根：.../kylin-ai-cryptojacking-detect
# -----------------------------
THIS_DIR = Path(__file__).resolve().parent                      # .../miner_sentinel_l1/src
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

PROJECT_ROOT = THIS_DIR.parents[3] if len(THIS_DIR.parents) >= 3 else THIS_DIR
DEFAULT_L2_ENTRY = PROJECT_ROOT / "src" / "miner_sentinel_l2" / "src" / "main.py"

from memory_monitor.memory_judge import MemoryJudge  # noqa: E402


# -----------------------------
# 配置加载
# 支持环境变量 MON_RULES 指定绝对路径
# -----------------------------
def find_config_path() -> Path:
    env_path = os.environ.get("MON_RULES")
    if env_path:
        p = Path(env_path).expanduser()
        if p.exists():
            return p
    candidates = [
        THIS_DIR / "memory_monitor" / "monitoring_rules.yaml",
        PROJECT_ROOT / "src" / "miner_sentinel_l1" / "src" / "memory_monitor" / "monitoring_rules.yaml",
        PROJECT_ROOT / "src" / "miner_sentinel_l1" / "memory_monitor" / "monitoring_rules.yaml",
        PROJECT_ROOT / "configs" / "monitoring_rules.yaml",
        Path.cwd() / "monitoring_rules.yaml",
        Path.cwd() / "memory_monitor" / "monitoring_rules.yaml",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError("monitoring_rules.yaml 未找到（可用环境变量 MON_RULES 指定绝对路径）")


def load_configuration() -> Dict[str, Any]:
    cfg_path = find_config_path()
    with cfg_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    # L2 候选挑选的可选配置
    data.setdefault("l2_candidates", {"topn": 12, "sample_secs": 1})
    return data


# -----------------------------
# 候选 PID 选择（Top-N）
# 综合 CPU/RSS/IO 得分；采样约 1s，不阻塞太久
# -----------------------------
def _score_row(cpu: float, rss: int, io_r: int, io_w: int) -> float:
    # 简单线性：权重可在此微调
    return cpu + (rss / 1e7) + ((io_r + io_w) / 1e6)


def pick_candidate_pids(topn: int = 12, sample_secs: float = 1.0) -> List[int]:
    # 预热 CPU 百分比基线
    for p in psutil.process_iter(["pid"]):
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass

    time.sleep(max(0.2, float(sample_secs)))  # 采样窗口

    rows: List[Tuple[int, float]] = []
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            pid = p.info["pid"]
            cpu = float(p.cpu_percent(interval=None))
            mem = p.info.get("memory_info")
            rss = int(getattr(mem, "rss", 0) or 0)
            try:
                io = p.io_counters()
                io_r, io_w = int(getattr(io, "read_bytes", 0) or 0), int(getattr(io, "write_bytes", 0) or 0)
            except Exception:
                io_r = io_w = 0
            score = _score_row(cpu, rss, io_r, io_w)
            rows.append((pid, score))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    rows.sort(key=lambda x: x[1], reverse=True)
    return [pid for pid, _ in rows[:max(1, int(topn))]]


# -----------------------------
# 运行 L2 扫描（子进程 + JSON）
# 支持将 --pids 传给 L2；若 L2 不支持该参数，会自动回退到全量 --scan
# -----------------------------
def run_l2_scan(
    python_bin: Optional[str] = None,
    l2_entry: Optional[Path] = None,
    timeout_sec: int = 240,
    pids: Optional[List[int]] = None,
) -> Dict[str, Any]:
    py = python_bin or sys.executable
    entry = (l2_entry or DEFAULT_L2_ENTRY).resolve()
    if not entry.exists():
        return {"error": "l2_entry_not_found", "entrypoint": str(entry)}

    base_cmd = [py, str(entry), "--scan", "--json"]

    def _do_run(cmd: List[str]) -> Dict[str, Any]:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout_sec)
        if proc.returncode != 0:
            return {"error": "l2_nonzero_exit", "code": proc.returncode, "stderr": proc.stderr[:2000], "cmd": cmd}
        try:
            return json.loads(proc.stdout)
        except Exception as e:
            return {"error": "l2_bad_json", "detail": str(e), "stdout": proc.stdout[:2000], "stderr": proc.stderr[:1000]}

    # 优先尝试带 --pids
    if pids:
        cmd = base_cmd + ["--pids", ",".join(map(str, pids))]
        out = _do_run(cmd)
        # 若是不认识该参数，则回退一次全量扫描
        if out.get("error") in ("l2_nonzero_exit", "l2_bad_json") and "unrecognized arguments: --pids" in str(out):
            out = _do_run(base_cmd)
        return out

    return _do_run(base_cmd)


# -----------------------------
# 主循环
# -----------------------------
def main():
    config = load_configuration()
    detector = MemoryJudge(config, PROJECT_ROOT)

    sampling_interval = int(config.get("sampling_interval_seconds", 2))
    cooldown_period = int(config.get("cooldown_period_seconds", 120))
    recovery_config = config.get("recovery_conditions", {}) or {}

    # L2 参数（可被环境变量覆盖）
    l2_entry_env = os.environ.get("L2_ENTRY")
    l2_timeout_env = os.environ.get("L2_TIMEOUT")
    l2_python_env = os.environ.get("L2_PY")

    l2_entry = Path(l2_entry_env).expanduser() if l2_entry_env else DEFAULT_L2_ENTRY
    l2_timeout = int(l2_timeout_env) if l2_timeout_env else 240
    l2_python = l2_python_env or sys.executable

    # 候选 PID 配置
    cand_cfg = config.get("l2_candidates", {}) or {}
    cand_topn = int(cand_cfg.get("topn", 12))
    cand_sample_secs = float(cand_cfg.get("sample_secs", 1.0))

    print("[L1] MiningDetector 已启动", flush=True)

    # 初始状态
    if not hasattr(detector, "last_alert_time"):
        detector.last_alert_time = 0.0
    prev_status = "NORMAL"

    try:
        while True:
            cycle_start = time.time()

            # 采集原始指标
            raw_metrics = detector.metrics_collector.collect_all_metrics()
            current_time = time.time()

            # 更新窗口
            for metric_name, value in raw_metrics.items():
                if metric_name in detector.metric_windows:
                    detector.metric_windows[metric_name].add_value(value, current_time)

            # 聚合
            windowed_metrics: Dict[str, float] = {}
            for metric_name, window in detector.metric_windows.items():
                if metric_name in ["pgmajfault_per_sec", "pswpin_per_sec", "pswpout_per_sec"]:
                    windowed_metrics[metric_name] = window.calculate_median()
                else:
                    windowed_metrics[metric_name] = window.calculate_mean()

            # 评分/状态
            total_score, component_scores, category_count = detector.analyzer.calculate_total_score(windowed_metrics)
            status = detector.analyzer.determine_status(total_score, category_count)

            # 恢复判定
            is_healthy = detector._check_recovery_conditions(raw_metrics, recovery_config)
            if is_healthy:
                detector.consecutive_healthy_samples += 1
            else:
                detector.consecutive_healthy_samples = 0

            required_healthy_samples = max(1, int((recovery_config.get("recovery_time_seconds", 20)) / max(1, sampling_interval)))
            if detector.consecutive_healthy_samples >= required_healthy_samples:
                for window in detector.metric_windows.values():
                    window.clear()
                status = "NORMAL"
                total_score = 0
                category_count = 0
                component_scores = {}
                detector.consecutive_healthy_samples = 0

            # 常规心跳
            heartbeat = detector._create_heartbeat_message(
                cycle_start, status, total_score, category_count, windowed_metrics, component_scores
            )
            print(json.dumps(heartbeat, ensure_ascii=False), flush=True)

            # 触发条件：首次跃迁 or 冷却到期
            should_trigger = False
            if status in ("WARNING", "CRITICAL"):
                rising_edge = (prev_status == "NORMAL")
                cooldown_ok = (current_time - detector.last_alert_time) >= cooldown_period
                should_trigger = rising_edge or cooldown_ok

            if should_trigger:
                detector._log_event(current_time, status, total_score, category_count, heartbeat)
                detector.last_alert_time = current_time

                # 选 Top-N 候选 PID（约 1 秒）
                candidates = pick_candidate_pids(topn=cand_topn, sample_secs=cand_sample_secs)

                # 调 L2（带 --pids），拿 JSON
                l2_payload = run_l2_scan(
                    python_bin=l2_python,
                    l2_entry=l2_entry,
                    timeout_sec=l2_timeout,
                    pids=candidates,
                )

                # 输出 L2 心跳
                l2_heartbeat = {
                    "ts": time.time(),
                    "level": "L2_SCAN",
                    "l1_status": status,
                    "l1_score": total_score,
                    "l1_categories": category_count,
                    "candidates": candidates,
                    "l2_result": l2_payload,  # {results:[...]} 或 {error:...}
                }
                print(json.dumps(l2_heartbeat, ensure_ascii=False), flush=True)

            # 频率控制
            time_spent = time.time() - cycle_start
            time.sleep(max(0.0, sampling_interval - time_spent))

            prev_status = status

    except KeyboardInterrupt:
        print("\n[L1] 监控程序已停止")


if __name__ == "__main__":
    main()

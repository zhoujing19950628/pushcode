#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
L1 主程序：系统级内存/压力监控
- 连续心跳打印（JSON）
- 依据监控规则聚合窗口、计算得分与状态（NORMAL/WARNING/CRITICAL）
- 状态恢复后清空窗口
- 在 WARNING/CRITICAL 的跃迁或冷却到期时，仅记录事件日志（不再触发任何 L2 逻辑）

可选环境变量：
- MON_RULES : 规则文件 monitoring_rules.yaml（绝对路径）
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import Dict, Any
import yaml


# l1_main.py 里补一个最小函数（可放到文件顶部 utilities 区域）：
import subprocess, sys
from pathlib import Path
from typing import Any, Dict

# ====== 放在文件顶部 imports 后面 ======
import os, sys, json, time, subprocess, threading

def run_ml_bridge_async(repo_root, config):
    bridge = os.environ.get("MINER_ML_BRIDGE") or str(repo_root / "src/miner_sentinel_ml_bridge" / "score_topn_processes.py")
    model  = os.environ.get("MINER_ML_MODEL")  or str(repo_root / "src/miner_sentinel_ml-l2" / "out_rf" / "rf_model.joblib")
    sample_topn = int(os.environ.get("MINER_ML_TOPN", 10))        # 采样前 10
    display_top = int(os.environ.get("MINER_ML_DISPLAY_TOP", 5))  # 摘要前 5
    dur    = int(os.environ.get("MINER_ML_DURATION", 120))
    interval = float(os.environ.get("MINER_ML_INTERVAL", 1.0))
    thr    = os.environ.get("MINER_ML_THR")

    cmd = [sys.executable, bridge, "--model", model,
           "--topn", str(sample_topn), "--duration", str(dur),
           "--interval", str(interval), "--json"]
    if thr:
        cmd += ["--thr", str(thr)]

    try:
        proc = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[L1] ML spawned pid={proc.pid} cmd={' '.join(cmd)}", flush=True)

        def _pump_stdout():
            last_line = ""
            try:
                assert proc.stdout is not None
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    if line:
                        # 原样把 L2 的 JSON 打出来（L2 结束时会来这一行）
                        print(line, flush=True)
                        last_line = line
            finally:
                # L2 结束：再打印 Top-5 摘要
                try:
                    if last_line:
                        obj = json.loads(last_line)
                        results = obj.get("results", [])
                        if results:
                            brief = ", ".join([f"{r.get('pid')}:{(r.get('name') or '')[:24]}" for r in results[:display_top]])
                            print(f"[L1] ML Top{display_top} by prob => {brief}", flush=True)
                        else:
                            print("[L1] ML produced empty results.", flush=True)
                    else:
                        print("[L1] ML produced no stdout.", flush=True)
                except Exception as e:
                    print(f"[L1] ML output parse error: {e}", flush=True)

        def _pump_stderr():
            try:
                assert proc.stderr is not None
                for line in proc.stderr:
                    line = line.rstrip("\n")
                    if line:
                        print(f"[L1][ML][stderr] {line}", flush=True)
            except Exception:
                pass

        threading.Thread(target=_pump_stdout, daemon=True).start()
        threading.Thread(target=_pump_stderr, daemon=True).start()
        return proc
    except Exception as e:
        print(f"[L1] ML bridge spawn error: {e}", flush=True)
        return None


# ---- 路径基准 ----
THIS_FILE = Path(__file__).resolve()                           # .../pushcode/src/miner_sentinel_l1/src/l1_main.py
THIS_DIR  = THIS_FILE.parent                                   # .../pushcode/src/miner_sentinel_l1/src
# 期望 SRC_DIR = .../pushcode/src
SRC_DIR   = THIS_DIR.parents[2] if len(THIS_DIR.parents) >= 2 else THIS_DIR
# 期望 REPO_ROOT = .../pushcode
REPO_ROOT = SRC_DIR.parent if SRC_DIR.name == "src" else SRC_DIR

# 让内部包可导入
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from memory_monitor.memory_judge import MemoryJudge  # noqa: E402


# ---- 配置加载 ----
def find_rules() -> Path:
    env = os.environ.get("MON_RULES")
    if env:
        p = Path(env).expanduser()
        if p.exists():
            return p
    candidates = [
        THIS_DIR / "memory_monitor" / "monitoring_rules.yaml",
        SRC_DIR / "miner_sentinel_l1" / "src" / "memory_monitor" / "monitoring_rules.yaml",
        SRC_DIR / "miner_sentinel_l1" / "memory_monitor" / "monitoring_rules.yaml",
        REPO_ROOT / "configs" / "monitoring_rules.yaml",
        Path.cwd() / "monitoring_rules.yaml",
        Path.cwd() / "memory_monitor" / "monitoring_rules.yaml",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError(
        "monitoring_rules.yaml 未找到；可设置 MON_RULES 为绝对路径，"
        f"例如：export MON_RULES={SRC_DIR}/miner_sentinel_l1/src/memory_monitor/monitoring_rules.yaml"
    )


def load_configuration() -> Dict[str, Any]:
    cfg = find_rules()
    with cfg.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    # 不再注入任何 L2 默认项
    return data


# ---- 运行目录（事件日志等）----
def ensure_runtime_dir() -> Path:
    run_dir = REPO_ROOT / "runtime" / "logs"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


# ---- 主循环 ----
# --- 完整 main()：带“连续≥30s 才触发 + 冷却 + 异步 L2” ---
def main():
    # 不需要任何目录，直接跑
    config = load_configuration()
    detector = MemoryJudge(config, REPO_ROOT)

    sampling_interval = int(config.get("sampling_interval_seconds", 2))
    cooldown_period   = int(config.get("cooldown_period_seconds", 120))
    recovery_config   = config.get("recovery_conditions", {}) or {}
    trigger_cfg = config.get("trigger", {}) or {}
    dwell_warning  = int(trigger_cfg.get("dwell_seconds_warning", 30))
    dwell_critical = int(trigger_cfg.get("dwell_seconds_critical", 30))

    print("[L1] MiningDetector started", flush=True)
    print(f"[L1] REPO_ROOT={REPO_ROOT}", flush=True)

    prev_status = "NORMAL"
    danger_since = None
    l2_proc = None
    detector.last_alert_time = getattr(detector, "last_alert_time", 0.0)

    try:
        while True:
            # 一次检测
            out = detector.run_detection_cycle()
            now      = out["current_time"]
            status   = out["status"]
            total    = out["total_score"]
            cat_cnt  = out["category_count"]
            raw      = out["raw_metrics"]
            win      = out["windowed_metrics"]
            comp     = out["component_scores"]
            cycle_st = out["cycle_start"]

            # 心跳：打印到屏幕
            hb = detector._create_heartbeat_message(cycle_st, status, total, cat_cnt, win, comp)
            print(json.dumps(hb, ensure_ascii=False), flush=True)

            # 恢复逻辑（不打印不落盘）
            detector.check_recovery_and_reset(raw, sampling_interval, recovery_config)

            # 连续危险计时
            if status in ("WARNING", "CRITICAL"):
                if prev_status == "NORMAL" or danger_since is None:
                    danger_since = now
            else:
                danger_since = None

            need_dwell = dwell_warning if status == "WARNING" else (dwell_critical if status == "CRITICAL" else 0)
            dwell_ok   = (danger_since is not None) and ((now - danger_since) >= need_dwell)
            cooldown_ok = (now - detector.last_alert_time) >= cooldown_period
            l2_running = (l2_proc is not None) and (l2_proc.poll() is None)

            should_trigger = (status in ("WARNING", "CRITICAL")) and dwell_ok and cooldown_ok and (not l2_running)
            if should_trigger:
                detector.last_alert_time = now
                print(f"[L1] Trigger L2 (status={status}, dwell={need_dwell}s, cooldown_ok={cooldown_ok})", flush=True)
                l2_proc = run_ml_bridge_async(REPO_ROOT, config)

            # 控制频率
            elapsed = time.time() - cycle_st
            time.sleep(max(0.0, sampling_interval - elapsed))
            prev_status = status

    except KeyboardInterrupt:
        print("\n[L1] Stopped")


if __name__ == "__main__":
    main()

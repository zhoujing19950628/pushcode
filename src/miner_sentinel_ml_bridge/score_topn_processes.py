#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
L2: 采样 Top-N 进程特征 -> 随机森林打分 -> 输出 JSON（便于 L1/日志收集）
用法示例：
  python score_topn_processes.py --model /path/to/rf_model.joblib --topn 12 --duration 120 --interval 1 --json
"""

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import psutil

# --------------------------
# 工具：安全读取进程信息
# --------------------------
def safe(proc, fn, default=None):
    try:
        return fn(proc)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return default

def now_ts() -> int:
    return int(time.time())

@dataclass
class ProcSnap:
    pid: int
    name: str
    username: str
    cpu_percent: float
    rss_mb: float
    io_read_bytes: int
    io_write_bytes: int
    ctx_voluntary: int
    ctx_involuntary: int
    num_threads: int
    num_fds: Optional[int]

@dataclass
class ProcFeatAgg:
    pid: int
    name: str
    username: str
    # 我们输出的一批“通用特征”（会映射/对齐为模型 features）
    cpu_percent_mean: float
    rss_mb_mean: float
    io_read_bytes_per_sec: float
    io_write_bytes_per_sec: float
    ctx_voluntary_per_sec: float
    ctx_involuntary_per_sec: float
    num_threads_mean: float
    num_fds_mean: float

# --------------------------
# 采样 & 聚合
# --------------------------
def snapshot_proc(proc: psutil.Process) -> Optional[ProcSnap]:
    with proc.oneshot():
        pid = proc.pid
        name = safe(proc, lambda p: p.name(), "")
        username = safe(proc, lambda p: p.username(), "")
        cpu_percent = safe(proc, lambda p: p.cpu_percent(None), 0.0)  # 需要先预热一次
        mem = safe(proc, lambda p: p.memory_info(), None)
        rss_mb = (mem.rss / (1024 * 1024)) if mem else 0.0
        io = safe(proc, lambda p: p.io_counters(), None)
        io_read = io.read_bytes if io else 0
        io_write = io.write_bytes if io else 0
        ctx = safe(proc, lambda p: p.num_ctx_switches(), None)
        ctx_vol = ctx.voluntary if ctx else 0
        ctx_invol = ctx.involuntary if ctx else 0
        num_threads = safe(proc, lambda p: p.num_threads(), 0)
        num_fds = safe(proc, lambda p: p.num_fds(), None)  # Linux 才有
    return ProcSnap(pid, name, username, float(cpu_percent), float(rss_mb),
                    int(io_read), int(io_write), int(ctx_vol), int(ctx_invol),
                    int(num_threads), None if num_fds is None else int(num_fds))

def pick_topn_by_cpu(n: int, warmup_sleep: float = 0.5) -> List[int]:
    # 先预热 cpu_percent 计数器
    for p in psutil.process_iter([]):
        safe(p, lambda x: x.cpu_percent(None), 0.0)
    time.sleep(warmup_sleep)
    pairs: List[Tuple[float, int]] = []
    for p in psutil.process_iter([]):
        val = safe(p, lambda x: x.cpu_percent(None), 0.0)
        if val is None:
            val = 0.0
        pairs.append((float(val), p.pid))
    pairs.sort(reverse=True)
    return [pid for _, pid in pairs[:max(1, n)]]

def collect_series(pids: List[int], duration: int, interval: float) -> Dict[int, List[ProcSnap]]:
    series: Dict[int, List[ProcSnap]] = {pid: [] for pid in pids}
    # 第一拍：初始化 cpu 百分比累积窗口
    for pid in pids:
        p = psutil.Process(pid)
        safe(p, lambda x: x.cpu_percent(None), 0.0)

    t_end = time.time() + duration
    while time.time() < t_end:
        for pid in list(series.keys()):
            try:
                p = psutil.Process(pid)
            except psutil.Error:
                # 进程已退出
                series.pop(pid, None)
                continue
            snap = snapshot_proc(p)
            if snap:
                series[pid].append(snap)
        time.sleep(max(0.05, interval))
    return series

def agg_features(snaps: List[ProcSnap], dt_total: float) -> ProcFeatAgg:
    if not snaps:
        # 不应该发生；上层会过滤
        return ProcFeatAgg(0, "", "", 0, 0, 0, 0, 0, 0, 0, 0)

    # 以相邻快照的差分估算速率
    def diff_sum(getter):
        s = 0
        for i in range(1, len(snaps)):
            cur = getter(snaps[i])
            prev = getter(snaps[i - 1])
            d = max(0, cur - prev)
            s += d
        return s

    pid = snaps[-1].pid
    name = snaps[-1].name
    username = snaps[-1].username

    cpu_mean = float(np.mean([s.cpu_percent for s in snaps])) if snaps else 0.0
    rss_mean = float(np.mean([s.rss_mb for s in snaps])) if snaps else 0.0

    read_d = diff_sum(lambda s: s.io_read_bytes)
    write_d = diff_sum(lambda s: s.io_write_bytes)
    ctxv_d = diff_sum(lambda s: s.ctx_voluntary)
    ctxi_d = diff_sum(lambda s: s.ctx_involuntary)

    rps = (read_d / dt_total) if dt_total > 0 else 0.0
    wps = (write_d / dt_total) if dt_total > 0 else 0.0
    ctxv_ps = (ctxv_d / dt_total) if dt_total > 0 else 0.0
    ctxi_ps = (ctxi_d / dt_total) if dt_total > 0 else 0.0

    threads_mean = float(np.mean([s.num_threads for s in snaps])) if snaps else 0.0
    fds = [s.num_fds for s in snaps if s.num_fds is not None]
    fds_mean = float(np.mean(fds)) if fds else 0.0

    return ProcFeatAgg(pid, name, username, cpu_mean, rss_mean, rps, wps, ctxv_ps, ctxi_ps, threads_mean, fds_mean)

# --------------------------
# 模型装载与特征对齐
# --------------------------
def load_bundle(path: str):
    bundle = joblib.load(path)
    model = bundle["model"]
    features = list(bundle["features"])
    thr = float(bundle.get("threshold", 0.5))
    feat_defaults = bundle.get("feature_defaults", None)  # 可选（见训练端补丁）
    return model, features, thr, feat_defaults

def to_row(model_features: List[str], feat_map: Dict[str, float], defaults: Optional[Dict[str, float]]) -> List[float]:
    row = []
    for f in model_features:
        if f in feat_map and feat_map[f] is not None:
            row.append(float(feat_map[f]))
        else:
            if defaults and f in defaults:
                row.append(float(defaults[f]))
            else:
                row.append(0.0)
    return row

def build_feature_map(agg: ProcFeatAgg) -> Dict[str, float]:
    """
    你训练集中的特征名若与这里不同，请：
      1) 在训练时把列名统一到以下这些；
      2) 或在部署时提供一个映射（此处也可扩展读取自定义映射）。
    """
    return {
        # 建议训练数据列就叫这些名字（简单直观）
        "cpu_percent_mean": agg.cpu_percent_mean,
        "rss_mb_mean": agg.rss_mb_mean,
        "io_read_bytes_per_sec": agg.io_read_bytes_per_sec,
        "io_write_bytes_per_sec": agg.io_write_bytes_per_sec,
        "ctx_voluntary_per_sec": agg.ctx_voluntary_per_sec,
        "ctx_involuntary_per_sec": agg.ctx_involuntary_per_sec,
        "num_threads_mean": agg.num_threads_mean,
        "num_fds_mean": agg.num_fds_mean,
    }

# --------------------------
# 主流程
# --------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="path to rf_model.joblib")
    ap.add_argument("--topn", type=int, default=12)
    ap.add_argument("--duration", type=int, default=120, help="seconds to sample")
    ap.add_argument("--interval", type=float, default=1.0, help="sampling interval (s)")
    ap.add_argument("--thr", type=float, default=None, help="override threshold")
    ap.add_argument("--json", action="store_true", help="print a single JSON line as output")
    args = ap.parse_args()

    t_start = time.time()
    pids = pick_topn_by_cpu(args.topn)
    series = collect_series(pids, args.duration, args.interval)
    t_end = time.time()
    dt = max(0.001, t_end - t_start)

    model, model_features, thr, feat_defaults = load_bundle(args.model)
    if args.thr is not None:
        thr = float(args.thr)

    results = []
    X = []
    alive = []
    for pid, snaps in series.items():
        if not snaps:
            continue
        agg = agg_features(snaps, dt)
        feat_map = build_feature_map(agg)
        row = to_row(model_features, feat_map, feat_defaults)
        X.append(row)
        alive.append((pid, agg))

    if not X:
        out = {
            "level": "L2_ML_PERPROC",
            "timestamp": now_ts(),
            "error": "no process samples",
        }
        print(json.dumps(out, ensure_ascii=False))
        return

    prob = model.predict_proba(np.asarray(X))[:, 1]
    for (pid, agg), p in zip(alive, prob):
        label = int(p >= thr)
        results.append({
            "pid": pid,
            "name": agg.name,
            "user": agg.username,
            "prob": float(p),
            "label": label,
            "features_used": build_feature_map(agg),  # 便于调试
        })

    out = {
        "level": "L2_ML_PERPROC",
        "timestamp": now_ts(),
        "model_thr": thr,
        "model_features": model_features,
        "count": len(results),
        "results": sorted(results, key=lambda r: r["prob"], reverse=True),
        "sample": {
            "duration": args.duration,
            "interval": args.interval,
            "topn": args.topn,
        }
    }
    if args.json:
        print(json.dumps(out, ensure_ascii=False))
    else:
        print(json.dumps(out, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()

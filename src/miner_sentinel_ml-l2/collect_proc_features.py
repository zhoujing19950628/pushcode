#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进程级特征采集器（每秒/按PID输出一行）
依赖：psutil  (pip install psutil)

输出字段（每进程一行）：
- timestamp, pid, name, cmdline
- cpu_pct
- mem_pct, rss_mb
- io_read_kbps, io_write_kbps, biopattern_COUNT/s, biopattern_KBYTES/s
- biopattern_RND(%), biopattern_SEQ(%)  # 无 eBPF 时为 -1
- tcpstates_NEWSTATE (以当前连接状态众数近似)
- bindsnoop_PROT_TCP, bindsnoop_PROT_UDP (进程是否处于 LISTEN)
- pidpersec_PID/s  # 该进程作为父进程的 fork 速率（近似）
- cachestat_HITS, cachestat_BUFFERS(MB), cachestat_CACHED(MB)  # 无 eBPF 时 HITS=-1，其余为主机级近似

用法示例：
  python3 collect_proc_features.py --interval 1 --duration 60 --topn 50 --out proc_features.jsonl
"""

import argparse, time, json, os, sys, psutil, socket
from collections import defaultdict, Counter
from pathlib import Path

TCP_STATE_CODE = {
    "ESTABLISHED": 1, "SYN_SENT": 2, "SYN_RECV": 3, "FIN_WAIT1": 4, "FIN_WAIT2": 5,
    "TIME_WAIT": 6, "CLOSE": 7, "CLOSE_WAIT": 8, "LAST_ACK": 9, "CLOSING": 10, "LISTEN": 11
}

def ram_usage_pct():
    vm = psutil.virtual_memory()
    # 近似对齐论文“USED(%)”：用率 = 100 - available/total*100
    return 100.0 - (vm.available / vm.total * 100.0)

def mem_buffers_cached_mb():
    # 读取 /proc/meminfo（便于填充 BUFFERS/CACHED 近似）
    buffers = cached = 0.0
    try:
        with open("/proc/meminfo","r") as f:
            for line in f:
                if line.startswith("Buffers:"):
                    buffers = float(line.split()[1]) / 1024.0
                elif line.startswith("Cached:"):
                    cached = float(line.split()[1]) / 1024.0
    except Exception:
        pass
    return buffers, cached

def most_common_tcp_state(conns):
    # 选“当前状态”的众数作为 NEWSTATE 近似
    cnt = Counter([c.status for c in conns if c.status])
    if not cnt:
        return -1
    st = cnt.most_common(1)[0][0]
    return TCP_STATE_CODE.get(st.upper(), -1)

def bool_int(x): return 1 if x else 0

def list_pids_topn(topn=None):
    procs = []
    for p in psutil.process_iter(attrs=["pid","name"]):
        try:
            procs.append(p)
        except Exception:
            continue
    if topn is None:
        return procs
    # 先初始化 cpu 百分比
    for p in procs:
        try: p.cpu_percent(None)
        except Exception: pass
    time.sleep(0.1)
    scored = []
    for p in procs:
        try: scored.append((p.cpu_percent(None), p))
        except Exception: continue
    scored.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in scored[:topn]]

def main():
    ap = argparse.ArgumentParser(description="Per-process mining feature collector")
    ap.add_argument("--interval", type=float, default=1.0, help="seconds between samples")
    ap.add_argument("--duration", type=int, default=0, help="total seconds (0=run forever)")
    ap.add_argument("--topn", type=int, default=50, help="monitor top-N CPU processes (None=all)")
    ap.add_argument("--out", type=str, default="proc_features.jsonl", help="output file (.jsonl or .csv)")
    args = ap.parse_args()

    fmt_csv = args.out.endswith(".csv")
    fout = open(args.out, "w", encoding="utf-8")

    # 维护增量基准：io 与 fork 计数（父->子）
    prev_io = {}         # pid -> (read_bytes, write_bytes, read_count, write_count, ts)
    prev_children = defaultdict(int)  # ppid -> children_seen
    # 预热 cpu 百分比
    for p in psutil.process_iter():
        try: p.cpu_percent(None)
        except Exception: pass

    # CSV 头
    header = [
        "timestamp","pid","name","cmdline",
        "cpu_pct","mem_pct","rss_mb",
        "io_read_kbps","io_write_kbps","biopattern_COUNT","biopattern_KBYTES",
        "biopattern_RND(%)","biopattern_SEQ(%)",
        "tcpstates_NEWSTATE","bindsnoop_PROT_TCP","bindsnoop_PROT_UDP",
        "pidpersec_PID/s","cachestat_HITS","cachestat_BUFFERS(MB)","cachestat_CACHED(MB)"
    ]
    if fmt_csv:
        fout.write(",".join(header) + "\n"); fout.flush()

    start = time.time()
    try:
        while True:
            t0 = time.time()
            rows = []
            # 选择进程集合
            procs = list_pids_topn(args.topn)

            # host 级缓存近似
            buffers_mb, cached_mb = mem_buffers_cached_mb()

            # 枚举进程
            for p in procs:
                try:
                    pid = p.pid
                    name = p.name()
                    try:
                        cmdline = " ".join(p.cmdline())[:2048]
                    except Exception:
                        cmdline = name
                    cpu = p.cpu_percent(None)  # 相对上一次调用
                    mem_pct = p.memory_percent()
                    rss_mb = p.memory_info().rss / (1024*1024)

                    # IO 增量
                    ioc = p.io_counters() if p.is_running() else None
                    read_b = getattr(ioc, "read_bytes", 0) if ioc else 0
                    write_b = getattr(ioc, "write_bytes", 0) if ioc else 0
                    read_c = getattr(ioc, "read_count", 0) if ioc else 0
                    write_c = getattr(ioc, "write_count", 0) if ioc else 0
                    now = time.time()
                    dt = args.interval

                    if pid in prev_io:
                        pr, pw, prc, pwc, pts = prev_io[pid]
                        dt = max(1e-6, now - pts)
                        dr = max(0, read_b - pr)
                        dw = max(0, write_b - pw)
                        drc = max(0, read_c - prc)
                        dwc = max(0, write_c - pwc)
                    else:
                        dr = dw = drc = dwc = 0

                    prev_io[pid] = (read_b, write_b, read_c, write_c, now)

                    io_read_kbps  = dr / dt / 1024.0
                    io_write_kbps = dw / dt / 1024.0
                    biop_count    = (drc + dwc) / dt   # 次/秒
                    biop_kbytes   = (dr + dw) / dt / 1024.0

                    # 网络：连接状态与是否 listen（TCP/UDP）
                    cons = []
                    try:
                        cons = p.connections(kind='inet')
                    except Exception:
                        cons = []
                    state_code = most_common_tcp_state(cons)
                    listen_tcp = any(c.status == psutil.CONN_LISTEN and c.type == socket.SOCK_STREAM for c in cons)
                    listen_udp = any(c.status == psutil.CONN_NONE  and c.type == socket.SOCK_DGRAM for c in cons)

                    # 该进程“每秒新建子进程数”（近似 pid/s）：统计 children 数变化
                    try:
                        children_now = len(p.children(recursive=False))
                    except Exception:
                        children_now = 0
                    prev = prev_children[pid]
                    pid_persec = max(0, children_now - prev) / max(1e-6, args.interval)
                    prev_children[pid] = children_now

                    row = [
                        int(now), pid, name, cmdline.replace(",", " ").replace("\n"," "),
                        round(cpu,3), round(mem_pct,3), round(rss_mb,3),
                        round(io_read_kbps,3), round(io_write_kbps,3), round(biop_count,3), round(biop_kbytes,3),
                        -1.0, -1.0,  # RND/SEQ 占位（无 eBPF）
                        int(state_code), bool_int(listen_tcp), bool_int(listen_udp),
                        round(pid_persec,3), -1, round(buffers_mb,3), round(cached_mb,3)
                    ]
                    rows.append(row)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            # 写出
            if fmt_csv:
                for r in rows:
                    fout.write(",".join(map(str, r)) + "\n")
            else:
                for r in rows:
                    fout.write(json.dumps(dict(zip(header, r)), ensure_ascii=False) + "\n")
            fout.flush()

            # 终止判断/节拍
            if args.duration and (time.time() - start) >= args.duration:
                break
            elapsed = time.time() - t0
            time.sleep(max(0.0, args.interval - elapsed))
    except KeyboardInterrupt:
        pass
    finally:
        fout.close()

if __name__ == "__main__":
    main()

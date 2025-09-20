#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Optional

# -----------------------------
# 包路径设置：让 `src.*` 可被导入
# 当前文件位于 .../miner_sentinel_l2/src/main.py
# 将其父目录 .../miner_sentinel_l2 加入 sys.path
# -----------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 业务依赖
from src.detectors.behavior_detector import ComprehensiveMiningDetector  # noqa: E402
from src.utils.system_utils import SystemUtils  # noqa: E402
from src.models.detection_result import DetectionResult  # noqa: E402
from src.utils.whitelist_manager import WhitelistManager  # noqa: E402

# -----------------------------
# JSON 输出工具：只向“真正的 stdout”输出
# -----------------------------
_ORIG_STDOUT = sys.stdout


def _emit_json(obj) -> None:
    """只在 stdout 输出一条 JSON 行（其他日志都应走 stderr）。"""
    _ORIG_STDOUT.write(json.dumps(obj, ensure_ascii=False) + "\n")
    _ORIG_STDOUT.flush()


def _log(*args, **kwargs) -> None:
    """统一日志到 stderr，避免污染 --json 的 stdout。"""
    print(*args, file=sys.stderr, **kwargs)


def _serialize_result(r: DetectionResult) -> dict:
    """把内部结果对象序列化为 JSON 友好的 dict。"""
    return {
        "process_id": getattr(r, "process_id", None),
        "process_name": getattr(r, "process_name", None),
        "status": getattr(r, "status", None),
        "total_score": float(getattr(r, "total_score", 0.0) or 0.0),
        "confidence": float(getattr(r, "confidence", 0.0) or 0.0),
        "evidences": list(getattr(r, "evidences", []) or []),
    }


def _load_whitelist_path(cli_path: Optional[str]) -> Path:
    """解析白名单配置路径。优先用 CLI；否则默认 src/config/whitelist.yaml。"""
    if cli_path:
        p = Path(cli_path).expanduser().resolve()
        return p
    return (Path(__file__).resolve().parent / "config" / "whitelist.yaml").resolve()


class MiningDetectionSystem:
    def __init__(self, whitelist_path: Path):
        self.detector = ComprehensiveMiningDetector()
        self.utils = SystemUtils()
        self.detection_history: List[DetectionResult] = []

        self.whitelist_path = whitelist_path
        if whitelist_path.exists():
            _log(f"[L2] 使用白名单: {whitelist_path}")
            self.whitelist_manager = WhitelistManager(whitelist_path)
        else:
            _log(f"[L2] 警告：未找到白名单文件（{whitelist_path}），将不使用白名单。")
            # WhitelistManager 仍需要一个实例；如果你的实现允许空路径，这里可传 None
            try:
                self.whitelist_manager = WhitelistManager(whitelist_path)
            except Exception:
                # 兜底：提供一个最小“全不过滤”的替身
                class _NoopWL:
                    def is_whitelisted(self, *_args, **_kwargs):
                        return False
                self.whitelist_manager = _NoopWL()  # type: ignore

        self.stats = {
            "total_scanned": 0,
            "whitelisted": 0,
            "suspicious": 0,
            "confirmed": 0,
        }

    def scan_system(self) -> List[DetectionResult]:
        """扫描系统中所有进程；遇到异常要尽量继续。"""
        results: List[DetectionResult] = []
        try:
            processes = self.utils.get_all_processes()  # 期望返回 psutil.Process 列表
        except Exception as e:
            _log(f"[L2] 获取进程列表失败: {e}")
            return results

        _log(f"[L2] 开始扫描 {len(processes)} 个进程...")
        self.stats["total_scanned"] = len(processes)

        for process in processes:
            try:
                pid = getattr(process, "pid", None)
                # 有些平台上 name() 会抛异常
                try:
                    pname = process.name()
                except Exception:
                    pname = "<unknown>"

                # 白名单过滤
                try:
                    if self.whitelist_manager and self.whitelist_manager.is_whitelisted(process):
                        self.stats["whitelisted"] += 1
                        _log(f"[L2] 进程 {pid} 在白名单中, 跳过")
                        continue
                except Exception as e:
                    _log(f"[L2] 白名单判断异常（PID={pid}）: {e}")

                _log(f"[L2] 正在处理进程: PID={pid}, 名称={pname}")

                # 调用行为检测
                result: DetectionResult = self.detector.analyze_process(pid)
                if getattr(result, "status", "NORMAL") != "NORMAL":
                    results.append(result)
                    _log(f"[L2] 发现可疑进程: PID={pid}, 得分={getattr(result, 'total_score', 0.0):.2f}")
                else:
                    _log(f"[L2] 进程 {pid} 正常")

            except Exception as e:
                _log(f"[L2] 分析进程时出错（PID={getattr(process, 'pid', '?')}）: {e}")

        return results

    def monitor_system(self, interval: int = 30):
        """持续监控模式（非 JSON）。"""
        _log("[L2] 开始系统监控...")
        try:
            while True:
                start_time = time.time()

                results = self.scan_system()
                self._handle_results(results)

                elapsed = time.time() - start_time
                sleep_time = max(0, interval - elapsed)
                time.sleep(sleep_time)
        except KeyboardInterrupt:
            _log("\n[L2] 监控已停止")

    def _handle_results(self, results: List[DetectionResult]):
        """打印/处理检测结果（非 JSON 模式使用）。"""
        for result in results:
            self.detection_history.append(result)

            _log("\n=== 检测结果 ===")
            _log(f"进程: {getattr(result, 'process_name', '?')} (PID: {getattr(result, 'process_id', '?')})")
            _log(f"状态: {getattr(result, 'status', '?')}")
            _log(f"总得分: {float(getattr(result, 'total_score', 0.0) or 0.0):.2f}")
            _log(f"置信度: {float(getattr(result, 'confidence', 0.0) or 0.0):.2f}")

            evidences = list(getattr(result, "evidences", []) or [])
            if evidences:
                _log("证据:")
                for ev in evidences:
                    _log(f"  - {ev}")

            if getattr(result, "status", "") == "CONFIRMED":
                self._alert_confirmed_mining(result)

    def _alert_confirmed_mining(self, result: DetectionResult):
        _log("🚨 警报: 发现确认的挖矿进程!")
        _log(f"   进程: {getattr(result, 'process_name', '?')} (PID: {getattr(result, 'process_id', '?')})")
        _log("   建议立即处理!")
        # 这里可以添加自动处理逻辑，如终止进程等
        # self._terminate_process(result.process_id)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="挖矿行为检测系统 (L2)")
    p.add_argument("--scan", action="store_true", help="执行一次系统扫描")
    p.add_argument("--monitor", action="store_true", help="持续监控系统（非 JSON）")
    p.add_argument("--interval", type=int, default=30, help="监控间隔（秒）")
    p.add_argument("--json", action="store_true", help="仅在 stdout 输出一条 JSON，其他日志到 stderr")
    p.add_argument("--whitelist", type=str, default=None, help="白名单配置文件路径（可选）")
    return p.parse_args()


def main():
    args = parse_args()

    # --json 模式：把普通的 print 输出重定向到 stderr，避免污染 JSON
    if args.json:
        sys.stdout = sys.stderr

    whitelist_path = _load_whitelist_path(args.whitelist)
    detection_system = MiningDetectionSystem(whitelist_path)

    if args.scan:
        results = detection_system.scan_system()
        if args.json:
            payload = {
                "ts": time.time(),
                "source": "L2",
                "results": [_serialize_result(r) for r in results],
            }
            _emit_json(payload)  # 只向 stdout 写这一条
        else:
            detection_system._handle_results(results)

    elif args.monitor:
        detection_system.monitor_system(args.interval)

    else:
        # 默认打印帮助到 stderr
        _log("未指定模式，使用 --scan 或 --monitor。")
        _log("")
        parser = argparse.ArgumentParser(prog="main.py")
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # 上游（如 `| head`）关闭管道时，安静退出
        try:
            sys.stderr.write("Broken pipe, exit.\n")
        except Exception:
            pass
        sys.exit(0)

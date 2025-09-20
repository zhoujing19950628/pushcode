#!/usr/bin/env python3
"""
挖矿木马检测主程序 - 修复版：正确的层级联动逻辑
L1: 基于内存指标的异常检测 → 触发 L2进程扫描
L2: 基于进程行为的综合检测 → 触发 L3哈希验证
L3: 基于内存哈希的精确匹配检测
"""

import argparse
import json
import time
import sys
import threading
import queue
import os
import signal
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime
import yaml

# 添加项目根目录到Python路径
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.append(str(PROJECT_ROOT))

# 导入各层检测模块
try:
    from miner_sentinel_l1.src.memory_monitor.memory_judge import MemoryJudge
    from miner_sentinel_l2.src.detectors.behavior_detector import ComprehensiveMiningDetector
    from miner_sentinel_l2.src.utils.system_utils import SystemUtils
    from miner_sentinel_l2.src.models.detection_result import DetectionResult
    from miner_sentinel_l2.src.utils.whitelist_manager import WhitelistManager
    from miner_sentinel_l3.src.cryptojacking_trap_custom import MinerDetector
except ImportError as e:
    print(f"导入模块失败: {e}")
    print("请确保所有依赖的子模块都已正确安装和配置")
    sys.exit(1)


class CryptoJackingDetector:
    """修复版：正确的层级联动逻辑"""

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.running = False
        self.current_state = "L1_MONITORING"  # 当前状态：L1_MONITORING, L2_SCANNING, L3_VERIFYING

        # 初始化各层检测器
        self.l1_detector = self._init_l1_detector()
        self.l2_detector = self._init_l2_detector()
        self.system_utils = SystemUtils()

        # 检测结果和历史记录
        self.detection_history = []
        self.suspicious_pids = set()  # 可疑进程PID集合

        # 已知的挖矿进程哈希库
        self.miner_hashes = {
            'xmrig': 'abc123def4567890abcdef1234567890abcdef1234567890abcdef1234567890',
            'cpuminer': 'def456ghi7890123def456ghi7890123def456ghi7890123def456ghi7890123',
            'minerd': 'minerd1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
            # 添加更多已知挖矿程序的哈希
        }

        # 统计信息
        self.stats = {
            'l1_scans': 0,
            'l1_alerts': 0,
            'l2_scans': 0,
            'l2_suspicious': 0,
            'l3_verifications': 0,
            'l3_detections': 0,
            'confirmed_miners': 0
        }

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """加载配置文件"""
        default_config = {
            'l1_interval': 2,  # L1监控间隔(秒)
            'l2_scan_timeout': 30,  # L2扫描超时时间(秒)
            'l3_hash_threshold': 0.9375,
            'l1_trigger_threshold': 50,
            'alert_channels': {
                'console': True,
                'log_file': True
            }
        }

        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    user_config = yaml.safe_load(f) or {}
                    default_config.update(user_config)
            except Exception as e:
                print(f"加载配置文件失败: {e}, 使用默认配置")

        return default_config

    def _init_l1_detector(self) -> MemoryJudge:
        """初始化L1内存检测器"""
        l1_config = {
            "sampling_interval_seconds": self.config['l1_interval'],
            "cooldown_period_seconds": 120,
            "recovery_conditions": {
                'recovery_time_seconds': 20,
                'max_cpu_percent': 80,
                'max_memory_percent': 85
            }
        }
        return MemoryJudge(l1_config, PROJECT_ROOT)

    def _init_l2_detector(self) -> ComprehensiveMiningDetector:
        """初始化L2行为检测器"""
        return ComprehensiveMiningDetector()

    def run_l1_monitoring(self):
        """L1层内存监控 - 检测系统级异常"""
        print("[L1] 启动系统级内存指标监控...")

        while self.running and self.current_state == "L1_MONITORING":
            try:
                self.stats['l1_scans'] += 1

                # 采集和分析指标
                raw_metrics = self.l1_detector.metrics_collector.collect_all_metrics()
                current_time = time.time()

                # 更新滑动窗口
                for metric_name, value in raw_metrics.items():
                    if metric_name in self.l1_detector.metric_windows:
                        self.l1_detector.metric_windows[metric_name].add_value(value, current_time)

                # 计算聚合值
                windowed_metrics = {}
                for metric_name, window in self.l1_detector.metric_windows.items():
                    if metric_name in ["pgmajfault_per_sec", "pswpin_per_sec", "pswpout_per_sec"]:
                        windowed_metrics[metric_name] = window.calculate_median()
                    else:
                        windowed_metrics[metric_name] = window.calculate_mean()

                # 分析与评分
                total_score, component_scores, category_count = self.l1_detector.analyzer.calculate_total_score(
                    windowed_metrics)
                status = self.l1_detector.analyzer.determine_status(total_score, category_count)

                # ✅ 修复：只有当L1检测到系统级异常时才触发L2
                if total_score > self.config['l1_trigger_threshold']:
                    self.stats['l1_alerts'] += 1
                    print(f"🔔 [L1→L2] 系统异常(得分: {total_score})，启动L2进程扫描")
                    self.current_state = "L2_SCANNING"  # 切换到L2状态
                    return  # 退出L1监控，进入L2扫描

                time.sleep(self.config['l1_interval'])

            except Exception as e:
                print(f"[L1] 监控出错: {e}")
                time.sleep(self.config['l1_interval'])

    def run_l2_scanning(self):
        """L2层进程扫描 - 扫描所有进程寻找可疑行为"""
        print("[L2] 启动全进程扫描...")
        start_time = time.time()

        try:
            self.stats['l2_scans'] += 1
            processes = self.system_utils.get_all_processes()
            suspicious_found = False

            for process in processes:
                try:
                    # ✅ 修复：L2只有一种扫描模式，没有深度/常规之分
                    result = self.l2_detector.analyze_process(process.pid)

                    if result.status in ["SUSPICIOUS", "CONFIRMED"]:
                        suspicious_found = True
                        self.suspicious_pids.add(process.pid)
                        self.stats['l2_suspicious'] += 1

                        detection_info = {
                            'timestamp': datetime.now().isoformat(),
                            'level': 'L2',
                            'pid': process.pid,
                            'process_name': process.name(),
                            'status': result.status,
                            'score': result.total_score,
                            'confidence': result.confidence,
                            'message': f"可疑进程: {process.name()} (PID: {process.pid})"
                        }

                        print(f"⚠️  [L2可疑] {detection_info['message']}")
                        self._log_detection(detection_info)

                        # ✅ 修复：发现可疑进程立即触发L3验证
                        if result.status == "CONFIRMED":
                            print(f"🔔 [L2→L3] 确认可疑进程，启动L3验证 PID {process.pid}")
                            self.current_state = "L3_VERIFYING"
                            return process.pid  # 返回需要验证的PID

                except Exception as e:
                    print(f"[L2] 分析进程 {process.pid} 出错: {e}")
                    continue

            # ✅ 修复：如果没有发现可疑进程，返回L1继续监控
            if not suspicious_found:
                print("✅ [L2→L1] 未发现可疑进程，返回L1监控")
                self.current_state = "L1_MONITORING"
                return None

            # 如果只有可疑但没有确认，也返回L1（实际可根据需要调整）
            print("⚠️  [L2→L1] 发现可疑进程但未确认，返回L1持续监控")
            self.current_state = "L1_MONITORING"
            return None

        except Exception as e:
            print(f"[L2] 扫描出错: {e}")
            self.current_state = "L1_MONITORING"
            return None

    def run_l3_verification(self, target_pid: int):
        """L3层哈希验证 - 验证特定进程"""
        print(f"[L3] 启动进程 {target_pid} 的内存哈希验证...")

        try:
            self.stats['l3_verifications'] += 1

            # 获取进程名以选择目标哈希
            process_name = self._get_process_name(target_pid)
            target_hash = self.miner_hashes.get(process_name.lower(), None)

            if not target_hash:
                print(f"⚠️  [L3] 无已知哈希用于进程 {process_name}，返回L1")
                self.current_state = "L1_MONITORING"
                return False

            # 执行L3验证
            detector = MinerDetector(target_pid, target_hash)
            is_miner = detector.quick_scan('.', self.config['l3_hash_threshold'])

            if is_miner:
                self.stats['l3_detections'] += 1
                self.stats['confirmed_miners'] += 1
                print(f"🔥 [L3确认] PID {target_pid} 确认为挖矿进程!")
                self._take_mitigation_action(target_pid, process_name, target_hash)
            else:
                print(f"✅ [L3排除] PID {target_pid} 未检测到挖矿特征")

            # ✅ 修复：无论L3结果如何，都返回L1继续监控
            self.current_state = "L1_MONITORING"
            return is_miner

        except Exception as e:
            print(f"[L3] 验证出错: {e}")
            self.current_state = "L1_MONITORING"
            return False

    def _get_process_name(self, pid: int) -> str:
        """获取进程名"""
        try:
            return Path(f"/proc/{pid}/comm").read_text().strip()
        except:
            return f"unknown_{pid}"

    def _take_mitigation_action(self, pid: int, process_name: str, target_hash: str):
        """采取处置措施"""
        print(f"🛡️  [处置] 终止确认的挖矿进程 PID {pid} ({process_name})")

        try:
            # 尝试终止进程
            os.kill(pid, signal.SIGTERM)
            print(f"✅ 已发送终止信号给进程 {pid}")
        except ProcessLookupError:
            print(f"⚠️  进程 {pid} 已不存在")
        except PermissionError:
            print(f"❌ 权限不足，无法终止进程 {pid}")
        except Exception as e:
            print(f"❌ 终止进程出错: {e}")

        # 记录检测结果
        alert_msg = {
            'timestamp': datetime.now().isoformat(),
            'level': 'L3_CONFIRMED',
            'pid': pid,
            'process_name': process_name,
            'hash': target_hash,
            'action': 'process_terminated',
            'message': f"确认的挖矿活动已处置! PID: {pid}, 进程: {process_name}"
        }

        self._log_detection(alert_msg)

    def _log_detection(self, detection_info: Dict):
        """记录检测结果"""
        self.detection_history.append(detection_info)

        if self.config['alert_channels'].get('log_file', True):
            log_file = Path("cryptojacking_detections.log")
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(detection_info, ensure_ascii=False) + '\n')

    def start_monitoring(self):
        """启动综合监控 - 正确的三级联动"""
        if self.running:
            print("监控已在运行中")
            return

        self.running = True
        print("启动修复版三级挖矿检测监控...")
        print("✅ 正确的联动逻辑:")
        print("   L1 → L2: 系统异常时扫描进程")
        print("   L2 → L3: 发现确认可疑进程时验证")
        print("   L3 → L1: 无论结果如何都返回监控")

        try:
            target_pid_for_l3 = None

            while self.running:
                if self.current_state == "L1_MONITORING":
                    self.run_l1_monitoring()

                elif self.current_state == "L2_SCANNING":
                    target_pid_for_l3 = self.run_l2_scanning()

                elif self.current_state == "L3_VERIFYING" and target_pid_for_l3:
                    self.run_l3_verification(target_pid_for_l3)
                    target_pid_for_l3 = None

                time.sleep(0.1)  # 避免CPU占用过高

        except KeyboardInterrupt:
            print("\n接收到中断信号，停止监控...")
            self.stop_monitoring()

    def stop_monitoring(self):
        """停止监控"""
        self.running = False
        print("监控已停止")
        print(f"统计信息: {json.dumps(self.stats, indent=2, ensure_ascii=False)}")


def main():
    parser = argparse.ArgumentParser(description='挖矿木马检测主程序 - 修复版')
    parser.add_argument('--monitor', '-m', action='store_true',
                        help='持续监控模式（正确的三级联动）')
    parser.add_argument('--config', '-c', default='config.yaml', help='配置文件路径')
    parser.add_argument('--test', '-t', type=int, help='测试特定PID')

    args = parser.parse_args()

    detector = CryptoJackingDetector(args.config)

    if args.monitor:
        detector.start_monitoring()
    elif args.test:
        # 测试模式：直接验证特定PID
        process_name = detector._get_process_name(args.test)
        print(f"测试验证 PID {args.test} ({process_name})")
        # 这里可以添加测试逻辑
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

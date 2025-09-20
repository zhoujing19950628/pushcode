#!/usr/bin/env python3
"""
挖矿进程检测器 - 通过内存哈希匹配检测挖矿活动
支持64字符哈希值（256位）
"""
import argparse
import sys
import os
import re
from pathlib import Path
from datetime import datetime


class MinerDetector:
    def __init__(self, pid: int, target_hash: str):
        self.pid = pid
        self.target_hash = target_hash.lower()  # 统一转为小写
        self.memory_files = []

    def find_memory_files(self, directory: str = "."):
        """查找指定PID的内存转储文件"""
        pattern = re.compile(rf".*{self.pid}.*\.txt$")

        for file in Path(directory).iterdir():
            if file.is_file() and pattern.match(file.name):
                self.memory_files.append(file)

        print(f"找到 {len(self.memory_files)} 个内存转储文件")
        return self.memory_files

    def extract_hashes_from_file(self, file_path: str):
        """从内存文件中提取所有哈希值"""
        hashes = []
        # 匹配64字符的哈希值（256位）
        hash_pattern = re.compile(r'当前哈希:\s*([a-f0-9]{64})', re.IGNORECASE)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                hashes = hash_pattern.findall(content)
        except Exception as e:
            print(f"读取文件 {file_path} 时出错: {e}")

        return hashes

    def hash_similarity(self, hash1: str, hash2: str):
        """计算两个哈希值的相似度（0-1）"""
        if len(hash1) != 64 or len(hash2) != 64:
            return 0.0

        matching_chars = sum(1 for a, b in zip(hash1.lower(), hash2.lower()) if a == b)
        return matching_chars / 64

    def detect_miner(self, similarity_threshold: float = 0.9375):
        """检测挖矿进程"""
        if not self.memory_files:
            print("未找到内存转储文件，请先运行 read_log.py")
            return False

        print(f"开始检测 PID {self.pid}，目标哈希: {self.target_hash}")
        print(f"哈希长度: {len(self.target_hash)} 字符 (256位)")
        print(f"相似度阈值: {similarity_threshold * 100:.1f}%")
        print("-" * 70)

        detected = False
        total_matches = 0

        for file_path in self.memory_files:
            print(f"\n分析文件: {file_path.name}")

            hashes = self.extract_hashes_from_file(str(file_path))
            print(f"  找到 {len(hashes)} 个内存区域哈希")

            file_matches = 0
            for i, found_hash in enumerate(hashes):
                similarity = self.hash_similarity(found_hash, self.target_hash)

                if similarity >= similarity_threshold:
                    file_matches += 1
                    total_matches += 1
                    print(f"  匹配 #{file_matches}:")
                    print(f"    发现哈希: {found_hash}")
                    print(f"    目标哈希: {self.target_hash}")
                    print(f"    相似度: {similarity * 100:.1f}% ({int(similarity * 64)}/64 字符匹配)")
                    print(f"    可能包含挖矿代码!")

            if file_matches > 0:
                detected = True
                print(f"  ⚠️  在该文件中发现 {file_matches} 个匹配!")

        print("\n" + "=" * 70)
        if detected:
            print(f"🚨 检测结果: 发现挖矿活动!")
            print(f"   总共发现 {total_matches} 个内存区域匹配目标哈希")
            print(f"   进程 PID {self.pid} 可能正在运行挖矿程序")
            return True
        else:
            print("✅ 检测结果: 未发现挖矿活动")
            print(f"   目标哈希 {self.target_hash} 未在内存中找到")
            return False

    def quick_scan(self, directory: str = ".", similarity_threshold: float = 0.9375):
        """快速扫描所有内存文件"""
        self.find_memory_files(directory)
        return self.detect_miner(similarity_threshold)


def main():
    parser = argparse.ArgumentParser(description='挖矿进程检测器 - 支持64字符哈希')
    parser.add_argument('--pid', '-p', type=int, required=True, help='要检测的进程ID')
    parser.add_argument('--hash', '-H', type=str, required=True,
                        help='目标哈希值 (64字符十六进制, 256位)')
    parser.add_argument('--dir', '-d', default='.',
                        help='内存转储文件所在目录 (默认当前目录)')
    parser.add_argument('--threshold', '-t', type=float, default=0.9375,
                        help='相似度阈值 (0-1, 默认0.9375 = 60/64匹配)')
    parser.add_argument('--min-match', '-m', type=int, default=60,
                        help='最小匹配字符数 (默认60)')

    args = parser.parse_args()

    # 验证哈希格式
    if len(args.hash) != 64 or not re.match(r'^[a-f0-9]{64}$', args.hash, re.IGNORECASE):
        print("错误: 哈希值必须是64个十六进制字符 (256位)")
        sys.exit(1)

    # 验证目录存在
    if not Path(args.dir).exists():
        print(f"错误: 目录 {args.dir} 不存在")
        sys.exit(1)

    # 如果指定了最小匹配数，计算对应的阈值
    if args.min_match:
        if args.min_match < 32 or args.min_match > 64:
            print("错误: 最小匹配字符数必须在 32 到 64 之间")
            sys.exit(1)
        threshold = args.min_match / 64.0
    else:
        threshold = args.threshold

    # 验证阈值范围
    if threshold < 0.5 or threshold > 1.0:
        print("错误: 相似度阈值必须在 0.5 到 1.0 之间")
        sys.exit(1)

    print(f"使用阈值: {threshold:.4f} ({int(threshold * 64)}/64 字符匹配)")

    # 创建检测器并执行检测
    detector = MinerDetector(args.pid, args.hash)
    result = detector.quick_scan(args.dir, threshold)

    sys.exit(0 if not result else 1)


if __name__ == "__main__":
    main()

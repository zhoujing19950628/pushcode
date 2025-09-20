import os
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
import os
from pathlib import Path
from datetime import datetime



# ========== 常量定义 ==========
class AlgorithmConstants:
    MIN_SIZE_OF_HASH_SPLIT = 4
    MAX_SPLIT_LINE_WINDOW = 10  # 示例值
    MIN_HASH_COVERAGE = 95  # 95%
    MIN_HASH_OCCURRENCE_COUNT = 30
    MAX_HASH_LINE_WINDOW = 2


# ========== 数据模型 ==========
class SplitErrorType(Enum):
    NONE = "NONE"
    MISSED = "MISSED"
    TOO_SMALL = "TOO_SMALL"
    TOO_LATE = "TOO_LATE"


@dataclass
class SplitOccurrence:
    line_number: int
    line_idx: int

    def __str__(self):
        return f"SplitOccurrence(line={self.line_number}, idx={self.line_idx})"


@dataclass
class Split:
    longest_sub_string: str = ""
    hash_start_idx: int = 0
    line_start_idx: int = 0
    hash_absolute_idx: int = 0
    line_start_absolute_idx: int = 0
    file_line_number: int = 0
    split_occurrences: List[SplitOccurrence] = field(default_factory=list)
    split_error_type: SplitErrorType = SplitErrorType.NONE

    def adjust_hash_absolute_idx(self, hash_absolute_idx: int):
        self.hash_absolute_idx = self.hash_start_idx + hash_absolute_idx

    def adjust_line_start_absolute_idx(self, file_line_idx_from: int):
        self.line_start_absolute_idx = self.line_start_idx + file_line_idx_from

    def add_split_occurrence(self, split_occurrence: SplitOccurrence):
        self.split_occurrences.append(split_occurrence)

    def has_error(self) -> bool:
        return self.split_error_type != SplitErrorType.NONE

    def __lt__(self, other):
        return self.hash_absolute_idx < other.hash_absolute_idx

    def __str__(self):
        return f"Split('{self.longest_sub_string}', hash_idx={self.hash_absolute_idx}, error={self.split_error_type})"


@dataclass
class Section:
    split_content: str = ""
    line_number: int = 0
    line_idx: int = 0
    split_idx: int = 0
    error_type: SplitErrorType = SplitErrorType.NONE

    def __lt__(self, other):
        return self.split_idx < other.split_idx

    def __str__(self):
        return f"Section('{self.split_content}', line={self.line_number}, error={self.error_type})"


@dataclass
class HashOccurrence:
    hash_value: str
    sections: List[Section] = field(default_factory=list)
    is_preprocessed: bool = False
    hash_coverage_percentage: Optional[int] = None

    def preprocess(self):
        if self.is_preprocessed:
            return

        # 按哈希索引排序
        self.sections.sort()

        # 找到第一个有效section
        i = 0
        while i < len(self.sections) and self.sections[i].error_type != SplitErrorType.NONE:
            i += 1

        if i >= len(self.sections):
            self.is_preprocessed = True
            return

        last_line = self.sections[i].line_number
        i += 1

        # 检查时间邻近性
        for j in range(i, len(self.sections)):
            section = self.sections[j]
            if section.error_type == SplitErrorType.NONE:
                if section.line_number - last_line > AlgorithmConstants.MAX_SPLIT_LINE_WINDOW:
                    section.error_type = SplitErrorType.TOO_LATE
                last_line = section.line_number

        self.is_preprocessed = True

    def calculate_hash_coverage_percentage(self):
        self.preprocess()
        if self.hash_coverage_percentage is None:
            hash_coverage = 0
            for section in self.sections:
                if section.error_type == SplitErrorType.NONE:
                    hash_coverage += len(section.split_content)

            self.hash_coverage_percentage = 100 * hash_coverage // len(self.hash_value)
            print(f"Hash coverage percentage: {self.hash_coverage_percentage}% for hash: {self.hash_value}")

    def is_valid(self) -> bool:
        if not self.sections:
            return False
        elif len(self.sections) == 1:
            return self.sections[0].error_type == SplitErrorType.NONE
        else:
            self.calculate_hash_coverage_percentage()
            return self.hash_coverage_percentage > AlgorithmConstants.MIN_HASH_COVERAGE

    def get_start_line_number(self) -> int:
        self.preprocess()
        for section in self.sections:
            if section.error_type == SplitErrorType.NONE:
                return section.line_number
        raise ValueError("No valid section in hash occurrence")

    def get_end_line_number(self) -> int:
        self.preprocess()
        for i in range(len(self.sections) - 1, -1, -1):
            if self.sections[i].error_type == SplitErrorType.NONE:
                return self.sections[i].line_number
        raise ValueError("No valid section in hash occurrence")

    def get_info(self) -> str:
        self.preprocess()
        errors_count = {error_type: 0 for error_type in SplitErrorType}
        total_size = 0
        valid_count = 0
        max_size = 0

        for section in self.sections:
            if section.error_type == SplitErrorType.NONE:
                total_size += len(section.split_content)
                valid_count += 1
                max_size = max(max_size, len(section.split_content))
            else:
                errors_count[section.error_type] += 1

        avg_size = total_size / valid_count if valid_count > 0 else 0
        error_msg = " ".join([f"{k.value}={v}" for k, v in errors_count.items()])

        return (f"HashCoverage: {self.hash_coverage_percentage}%, "
                f"Sections: {len(self.sections)}, MaxSplit: {max_size}, "
                f"AvgSize: {avg_size:.1f}, Errors: {error_msg}")


@dataclass
class MiningOccurrence:
    hash_value: str
    accepted_hash_occurrences: List[HashOccurrence] = field(default_factory=list)

    def __str__(self):
        return f"MiningOccurrence(hash={self.hash_value}, occurrences={len(self.accepted_hash_occurrences)})"


# ========== 核心检测逻辑 ==========
class DetectorTextBase:
    def __init__(self):
        pass

    def start_detection(self, hash_value: str, file_path: str) -> List[MiningOccurrence]:
        """主检测入口"""
        print(f"Starting detection for hash: {hash_value}, file: {file_path}")
        start_time = time.time()

        mining_occurrences = self.find_all_mining_occurrences(hash_value, file_path)

        end_time = time.time()
        print(f"Detection completed in {end_time - start_time:.2f}s. "
              f"Found {len(mining_occurrences) if mining_occurrences else 0} mining occurrences.")

        return mining_occurrences

    def find_all_mining_occurrences(self, hash_value: str, file_path: str) -> List[MiningOccurrence]:
        """查找所有挖矿事件"""
        print(f"Finding mining occurrences for hash: {hash_value}")
        hash_occurrences = self.find_all_hash_occurrences(hash_value, file_path)

        if not hash_occurrences:
            return []

        # 简化版的挖矿事件检测
        mining_occurrence = MiningOccurrence(hash_value=hash_value)

        last_valid_line = None
        for ho in hash_occurrences:
            if ho.is_valid():
                if last_valid_line is None:
                    mining_occurrence.accepted_hash_occurrences.append(ho)
                    last_valid_line = ho.get_end_line_number()
                else:
                    current_start = ho.get_start_line_number()
                    if current_start - last_valid_line < AlgorithmConstants.MAX_HASH_LINE_WINDOW:
                        mining_occurrence.accepted_hash_occurrences.append(ho)
                        last_valid_line = ho.get_end_line_number()
                    else:
                        print(f"Hash occurrence skipped: too late (distance: {current_start - last_valid_line})")

        return [mining_occurrence] if mining_occurrence.accepted_hash_occurrences else []

    def find_all_hash_occurrences(self, hash_value: str, file_path: str) -> List[HashOccurrence]:
        """查找所有哈希出现事件"""
        print(f"Finding hash occurrences for hash: {hash_value}")
        splits = self.find_all_split_occurrences(hash_value, file_path)

        if not splits:
            return []

        # 获取最小出现次数
        assumed_hash_occ_count = self.get_assumed_hash_occ_count(splits)
        hash_occurrences = []

        for split_occ_idx in range(assumed_hash_occ_count):
            sections = []
            for split in splits:
                section = Section()
                if split.has_error():
                    section.error_type = split.split_error_type
                else:
                    if split_occ_idx < len(split.split_occurrences):
                        split_occurrence = split.split_occurrences[split_occ_idx]
                        section.line_number = split_occurrence.line_number
                        section.line_idx = split_occurrence.line_idx
                    else:
                        continue
                section.split_content = split.longest_sub_string
                section.split_idx = split.hash_absolute_idx
                sections.append(section)

            ho = HashOccurrence(hash_value=hash_value, sections=sections)
            if ho.is_valid():
                hash_occurrences.append(ho)
            else:
                print(f"WARN - Invalid hash occurrence: {ho.get_info()}")

        return hash_occurrences

    def get_assumed_hash_occ_count(self, splits: List[Split]) -> int:
        """获取最小出现次数"""
        count = float('inf')
        for split in splits:
            if not split.has_error():
                count = min(count, len(split.split_occurrences))
        return count if count != float('inf') else 0

    def find_all_split_occurrences(self, hash_value: str, file_path: str) -> List[Split]:
        """查找所有拆分出现"""
        print(f"Finding split occurrences for hash: {hash_value}")
        splits = self.split_hash(hash_value, file_path)

        # 检查碎片大小
        for split in splits:
            # if not split.has_error() and len(split.longest_sub_string) < AlgorithmConstants.MIN_SIZE_OF_HASH_SPLIT:
            if len(split.longest_sub_string) < AlgorithmConstants.MIN_SIZE_OF_HASH_SPLIT:
                split.split_error_type = SplitErrorType.TOO_SMALL

        return self.find_occurrences_for_given_splits(splits, file_path)

    def find_occurrences_for_given_splits(self, splits: List[Split], file_path: str) -> List[Split]:
        """为给定拆分查找所有出现位置"""
        if not splits:
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                line_number = 0
                for line in file:
                    line_number += 1
                    for split in splits:
                        if not split.has_error():
                            line_idx = line.find(split.longest_sub_string)
                            if line_idx != -1:
                                split_occurrence = SplitOccurrence(line_number, line_idx)
                                split.add_split_occurrence(split_occurrence)
        except IOError as e:
            print(f"Error reading file: {e}")
            return []

        return splits

    def split_hash(self, hash_value: str, file_path: str) -> List[Split]:
        """拆分哈希值"""
        print(f"Splitting hash: {hash_value}")
        accumulative_result = []
        self._split_hash_recursive(hash_value, file_path, 0, 1, 0, None, None, accumulative_result)
        accumulative_result.sort()
        return accumulative_result

    def _split_hash_recursive(self, hash_sub_str: str, file_path: str, hash_sub_str_absolute_idx: int,
                              file_line_number_from: int, file_line_idx_from: int, file_line_number_to: Optional[int],
                              file_line_idx_to: Optional[int], accumulative_result: List[Split]):
        """递归拆分哈希值的核心算法"""
        if not hash_sub_str:
            return

        # 基础检查
        if (file_line_number_to is not None and file_line_number_from > file_line_number_to):
            self._no_result_warn(hash_sub_str, file_path, hash_sub_str_absolute_idx, file_line_number_from,
                                 file_line_idx_from, file_line_number_to, file_line_idx_to, accumulative_result)
            return

        main_split = None

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                line_number = 0
                for line in file:
                    line_number += 1

                    # 跳过超出范围的行
                    if line_number < file_line_number_from:
                        continue
                    if file_line_number_to is not None and line_number > file_line_number_to:
                        break

                    # 处理行内容
                    line = self._get_line_substring(file_line_number_from, file_line_number_to, file_line_idx_from,
                                                    file_line_idx_to, line_number, line)

                    # 寻找最长公共子串
                    current_split = self.lcs(hash_sub_str, line)
                    if current_split:
                        current_split.file_line_number = line_number
                        if main_split is None or len(current_split.longest_sub_string) > len(
                                main_split.longest_sub_string):
                            main_split = current_split

        except IOError as e:
            print(f"Error reading file in recursive split: {e}")
            return

        if not main_split or not main_split.longest_sub_string:
            self._no_result_warn(hash_sub_str, file_path, hash_sub_str_absolute_idx, file_line_number_from,
                                 file_line_idx_from, file_line_number_to, file_line_idx_to, accumulative_result)
            return

        # 调整索引
        main_split.adjust_hash_absolute_idx(hash_sub_str_absolute_idx)
        if main_split.file_line_number == file_line_number_from:
            main_split.adjust_line_start_absolute_idx(file_line_idx_from)

        accumulative_result.append(main_split)
        print(f"Main split found: {main_split}")

        # 递归处理左侧
        if main_split.hash_start_idx != 0:
            hash_left_sub_str = hash_sub_str[:main_split.hash_start_idx]
            file_left_side_line_from = file_line_number_from
            file_left_side_line_idx_from = file_line_idx_from

            file_left_side_line_to = main_split.file_line_number
            file_left_side_line_idx_to = main_split.line_start_idx - 1 if main_split.line_start_idx > 0 else 0

            self._split_hash_recursive(hash_left_sub_str, file_path, hash_sub_str_absolute_idx,
                                       file_left_side_line_from, file_left_side_line_idx_from,
                                       file_left_side_line_to, file_left_side_line_idx_to, accumulative_result)

        # 递归处理右侧
        hash_split_end_idx = main_split.hash_start_idx + len(main_split.longest_sub_string)
        if hash_split_end_idx < len(hash_sub_str):
            hash_right_sub_str = hash_sub_str[hash_split_end_idx:]
            hash_right_sub_str_absolute_idx = hash_sub_str_absolute_idx + hash_split_end_idx

            file_right_side_line_from = main_split.file_line_number
            file_right_side_line_idx_from = main_split.line_start_idx + len(main_split.longest_sub_string)
            file_right_side_line_to = file_line_number_to
            file_right_side_line_idx_to = file_line_idx_to

            self._split_hash_recursive(hash_right_sub_str, file_path, hash_right_sub_str_absolute_idx,
                                       file_right_side_line_from, file_right_side_line_idx_from,
                                       file_right_side_line_to, file_right_side_line_idx_to, accumulative_result)

    def _get_line_substring(self, file_line_number_from: int, file_line_number_to: Optional[int],
                            file_line_idx_from: int, file_line_idx_to: Optional[int],
                            line_number: int, line: str) -> str:
        """获取行的子字符串"""
        # 简化实现，实际应根据具体边界处理
        return line

    def _no_result_warn(self, hash_sub_str: str, file_path: str, hash_sub_str_absolute_idx: int,
                        file_line_number_from: int, file_line_idx_from: int, file_line_number_to: Optional[int],
                        file_line_idx_to: Optional[int], accumulative_result: List[Split]):
        """处理无结果的情况"""
        print(f"WARN - No result for: {hash_sub_str}, absolute_idx: {hash_sub_str_absolute_idx}")
        split_with_error = Split()
        split_with_error.longest_sub_string = hash_sub_str
        split_with_error.hash_absolute_idx = hash_sub_str_absolute_idx
        split_with_error.split_error_type = SplitErrorType.MISSED
        accumulative_result.append(split_with_error)

    @staticmethod
    def lcs(hash_str: str, line: str) -> Optional[Split]:
        """寻找最长公共子串"""
        if not hash_str or not line:
            return None

        longest_share = ""
        result_split = None

        for hash_idx in range(len(hash_str)):
            for line_idx in range(len(line)):
                sub_length = 0
                while (hash_idx + sub_length < len(hash_str) and
                       line_idx + sub_length < len(line) and
                       hash_str[hash_idx + sub_length] == line[line_idx + sub_length]):
                    sub_length += 1

                if sub_length > len(longest_share):
                    longest_share = hash_str[hash_idx:hash_idx + sub_length]
                    result_split = Split()
                    result_split.longest_sub_string = longest_share
                    result_split.hash_start_idx = hash_idx
                    result_split.line_start_idx = line_idx

        return result_split


# ========== 使用示例 ==========


# ========== 生成真实的内存读取日志文件 ==========
def generate_realistic_memory_log():
    # 您的目标比特币区块哈希
    target_hash = "00000000000000000001dfa3213bb0bd764f8b95d935609a6809613a349d1dc4"

    # 将哈希拆分成多个部分，模拟内存读取的碎片化
    hash_parts = [
        target_hash[0:16],  # 0000000000000000
        target_hash[16:32],  # 0001dfa3213bb0bd
        target_hash[32:48],  # 764f8b95d935609a
        target_hash[48:64]  # 6809613a349d1dc4
    ]

    log_content = []

    # 添加一些随机内存读取
    log_content.append("2023/05/18 16:56:37      0x2cc996f6d30")
    log_content.append("2023/05/18 16:56:37 0xeebe9194946edb1ff80a168cf72a7")
    log_content.append("2023/05/18 16:56:37 0xc89760d6f60ed931d1937fbe3836c8")
    log_content.append("2023/05/18 16:56:37 0xdcc1ed364ec2f875")

    # 插入第一个哈希碎片
    log_content.append("2023/05/18 16:56:38 0x" + hash_parts[0] + "  # memory read operation")

    # 更多随机内存读取
    log_content.append("2023/05/18 16:56:38      0x2cc911e9070")
    log_content.append("2023/05/18 16:56:38 0x27af177d2f1d88ad")
    log_content.append("2023/05/18 16:56:38 0x1771ccf01a490d0a")

    # 插入第二个哈希碎片
    log_content.append("2023/05/18 16:56:39 0x" + hash_parts[1] + "a425a0a40c4eccd0")

    # 更多随机内存读取
    log_content.append("2023/05/18 16:56:39 0x537378e17cebf78")
    log_content.append("2023/05/18 16:56:39 0xc618f5ccae0adac4b76dc91c71114")
    log_content.append("2023/05/18 16:56:39 0x36a21aa21a290230")

    # 插入第三个哈希碎片（稍微分散）
    log_content.append("2023/05/18 16:56:40 0x65e6cad0f255d4aa" + hash_parts[2])

    # 更多随机内存读取
    log_content.append("2023/05/18 16:56:40 0x4728fbf39b314506")
    log_content.append("2023/05/18 16:56:40 0xb7efcad594ac9e2b")
    log_content.append("2023/05/18 16:56:40                0x1")

    # 插入第四个哈希碎片
    log_content.append("2023/05/18 16:56:41 0x50b122bb40540efa" + hash_parts[3])

    # 添加更多行使文件更真实
    for i in range(20):
        timestamp = f"2023/05/18 16:56:{41 + i}"
        hex_data = f"0x{os.urandom(8).hex()}"  # 随机16进制数据
        log_content.append(f"{timestamp} {hex_data}")

    return log_content



# ========== 修改后的使用示例 ==========
def main():
    # 示例使用
    detector = DetectorTextBase()

    # 示例哈希值（真实的比特币区块哈希）
    example_hash = "00000000000000000001dfa3213bb0bd764f8b95d935609a6809613a349d1dc4"

    # 示例监控文件路径
    current_dir = Path(__file__).parent
    project_root = current_dir.parent.parent  # src -> kylin-ai-cryptojacking-detect
    data_dir = project_root / 'data'
    example_log_file = data_dir / 'lg_memory_read_log_test.txt'
    example_log_file = data_dir / 'monitorLog-MinerGate-Monero-small.out'

    # # 生成真实的内存读取日志文件
    # log_content = generate_realistic_memory_log()
    # # 写入文件
    # with open(example_log_file, 'w') as f:
    #     for line in log_content:
    #         f.write(line + '\n')
    # print(f"Generated realistic memory log with {len(log_content)} lines")
    # print(f"Target hash: {example_hash}")
    # print("Hash parts are distributed throughout the log file")


    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    try:
        # 执行检测
        mining_occurrences = detector.start_detection(example_hash, example_log_file)
        if mining_occurrences:
            print("Potential cryptojacking detected!")
            for mo in mining_occurrences:
                print(f"Mining occurrence: {mo}")
                for ho in mo.accepted_hash_occurrences:
                    print(f"  Hash occurrence: {ho.get_info()}")
        else:
            print("No cryptojacking activity detected.")
    except Exception as e:
        print(f"Error during detection: {e}")
        import traceback
        traceback.print_exc()
    print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

if __name__ == "__main__":
    main()

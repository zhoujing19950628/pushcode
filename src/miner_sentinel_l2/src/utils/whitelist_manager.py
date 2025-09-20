import yaml
from pathlib import Path
from typing import List, Set, Dict, Optional
import psutil
import time


class WhitelistManager:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.trusted_keywords: Set[str] = set()
        self.exact_matches: Set[str] = set()
        self.user_whitelist: Set[str] = set()
        self.options: Dict = {}

        self._load_config()

    def _load_config(self):
        """加载白名单配置"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f) or {}
            print(f'config:{config}')
            self.trusted_keywords = set(config.get('trusted_processes', []))
            self.exact_matches = set(config.get('exact_matches', []))
            self.user_whitelist = set(config.get('user_whitelist', []))
            self.options = config.get('options', {})

        except FileNotFoundError:
            print(f"白名单配置文件未找到: {self.config_path}")
        except yaml.YAMLError as e:
            print(f"白名单配置文件解析错误: {e}")

    def is_whitelisted(self, process: psutil.Process) -> bool:
        """检查进程是否在白名单中"""
        try:
            process_name = process.name()
            cmdline = ' '.join(process.cmdline()).lower()

            # 1. 精确匹配检查
            if process_name in self.exact_matches:
                print(f"精确匹配: {process_name}")
                return True

            # 2. 关键词匹配检查
            if any(keyword.lower() in process_name.lower() for keyword in self.trusted_keywords):
                print(f"关键词匹配: {process_name}")
                return True

            if any(keyword.lower() in cmdline for keyword in self.trusted_keywords):
                print(f"关键词匹配: {cmdline}")
                return True

            # 3. 用户自定义白名单检查
            if any(keyword.lower() in process_name.lower() for keyword in self.user_whitelist):
                print(f"用户自定义白名单: {process_name}")
                return True

            if any(keyword.lower() in cmdline for keyword in self.user_whitelist):
                print(f"用户自定义白名单: {cmdline}")
                return True

            # # 4. 根据选项进行智能过滤
            # if self._should_skip_by_options(process):
            #     print(f"根据选项跳过: {process_name}")
            #     return True

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        return False

    def _should_skip_by_options(self, process: psutil.Process) -> bool:
        """根据配置选项判断是否跳过进程"""
        options = self.options

        # 跳过系统进程
        if options.get('skip_system_processes', False):
            try:
                if process.username() in ['root', 'system'] and process.ppid() == 1:
                    return True
            except:
                pass

        # 跳过低CPU进程
        if options.get('skip_low_cpu_processes', False):
            try:
                cpu_percent = process.cpu_percent(interval=0.1)
                if cpu_percent < options.get('cpu_threshold', 1.0):
                    return True
            except:
                pass

        # 跳过短生命周期进程
        if options.get('skip_short_lived_processes', False):
            try:
                create_time = process.create_time()
                uptime = time.time() - create_time
                if uptime < options.get('min_uptime_seconds', 300):
                    return True
            except:
                pass

        return False

    def add_to_whitelist(self, process_name: str, list_type: str = "user"):
        """动态添加进程到白名单"""
        if list_type == "exact":
            self.exact_matches.add(process_name)
        elif list_type == "trusted":
            self.trusted_keywords.add(process_name)
        else:
            self.user_whitelist.add(process_name)

        self._save_config()

    def _save_config(self):
        """保存配置到文件"""
        config = {
            'trusted_processes': list(self.trusted_keywords),
            'exact_matches': list(self.exact_matches),
            'user_whitelist': list(self.user_whitelist),
            'options': self.options
        }

        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

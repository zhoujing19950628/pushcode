import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
import asyncio
import websockets
import json
import threading
import os
import traceback
import random

# 配置参数
ENDPOINTS = [
    "wss://ws.blockchain.info/inv",
    "wss://blockchain.info/ws"
]
OUTPUT_FILE = os.path.abspath("blockchain_monitor.log")
DEBUG_LOG = os.path.abspath("blockchain_debug.log")

class BlockchainMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("虚拟货币区块链监控器 v2.6")
        self.setup_ui()
        self.setup_async()
        self.initialize_state()
        self.initialize_logs()

    def setup_ui(self):
        """构建用户界面"""
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 控制面板
        control_frame = ttk.LabelFrame(main_frame, text="控制")
        control_frame.pack(fill=tk.X, pady=5)

        ttk.Label(control_frame, text="端点选择:").grid(row=0, column=0, padx=5)
        self.endpoint_combo = ttk.Combobox(control_frame, values=ENDPOINTS, width=50)
        self.endpoint_combo.current(0)
        self.endpoint_combo.grid(row=0, column=1, padx=5)

        self.start_btn = ttk.Button(control_frame, text="启动监控", command=self.toggle_monitor)
        self.start_btn.grid(row=0, column=2, padx=5)

        # 区块信息显示
        info_frame = ttk.LabelFrame(main_frame, text="最新区块头信息")
        info_frame.pack(fill=tk.X, pady=5)

        self.info_text = tk.Text(info_frame, height=8, wrap=tk.WORD)
        self.info_text.pack(fill=tk.X, padx=5, pady=5)

        # 日志窗口
        log_frame = ttk.LabelFrame(main_frame, text="运行日志")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_area = scrolledtext.ScrolledText(log_frame, height=12)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def setup_async(self):
        """初始化异步环境"""
        self.loop = asyncio.new_event_loop()
        self.monitor_task = None
        self.keepalive_task = None
        threading.Thread(target=self.run_async_loop, daemon=True).start()

    def initialize_state(self):
        """初始化状态变量"""
        self.running = False
        self.ws_connection = None
        self.reconnect_attempts = 0
        self.current_endpoint = 0
        self.connection_active = False  # 新增连接状态标志

    def initialize_logs(self):
        """初始化日志文件"""
        for log_file in [OUTPUT_FILE, DEBUG_LOG]:
            try:
                if not os.path.exists(log_file):
                    with open(log_file, "w") as f:
                        if log_file == OUTPUT_FILE:
                            header = "区块哈希|区块高度|版本|前导区块|默克尔根|时间戳|难度目标|随机数|本地接收时间\n"
                            f.write(header)
            except Exception as e:
                self.log(f"初始化日志文件失败: {str(e)}", error=True)
            try:
                with open(log_file, "a") as f:
                    f.write(f"\n\n=== 监控会话开始于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            except Exception as e:
                self.log(f"初始化日志文件失败: {str(e)}", error=True)

    def run_async_loop(self):
        """运行异步事件循环"""
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def toggle_monitor(self):
        """切换监控状态"""
        if not self.running:
            self.start_monitoring()
        else:
            asyncio.run_coroutine_threadsafe(self.stop_monitoring(), self.loop)

    def start_monitoring(self):
        """启动监控"""
        self.running = True
        self.start_btn.config(text="停止监控")
        self.monitor_task = asyncio.run_coroutine_threadsafe(
            self.monitor_blocks(), 
            self.loop
        )
        self.log("监控已启动")
        self.info_text.delete(1.0, tk.END)

    async def stop_monitoring(self):
        """安全停止监控"""
        self.running = False
        self.start_btn.config(text="启动监控")
        
        if self.ws_connection and not self.connection_closed():
            await self.ws_connection.close()
        
        if self.monitor_task and not self.monitor_task.done():
            self.monitor_task.cancel()
        if self.keepalive_task and not self.keepalive_task.done():
            self.keepalive_task.cancel()
        
        self.log("监控已停止")

    def connection_closed(self):
        """判断连接状态的兼容方法"""
        try:
            return self.ws_connection.close_code is not None
        except:
            return True

    async def monitor_blocks(self):
        """增强型监控主循环"""
        while self.running:
            try:
                endpoint = ENDPOINTS[self.current_endpoint]
                self.log(f"尝试连接端点: {endpoint}")
                
                async with websockets.connect(
                    endpoint,
                    ping_interval=15,
                    ping_timeout=10,
                    close_timeout=5,
                    max_queue=1024,
                    additional_headers={
                        "User-Agent": "BTC-Monitor/2.6",
                        "Origin": "https://blockchain.info"
                    }
                ) as self.ws_connection:
                    self.connection_active = True
                    self.reconnect_attempts = 0
                    await self.ws_connection.send(json.dumps({"op": "blocks_sub"}))
                    self.log("区块订阅成功")
                    
                    self.keepalive_task = asyncio.create_task(self.keepalive())
                    
                    async for message in self.ws_connection:
                        if not self.running:
                            break
                        await self.process_message(message)
                        
            except Exception as e:
                await self.handle_connection_error(e)
            finally:
                await self.cleanup_connection()

    async def keepalive(self):
        """稳健心跳机制"""
        while self.running and self.connection_active:
            try:
                await asyncio.sleep(10)  # 缩短心跳间隔至10秒
                if self.connection_active and not self.connection_closed():
                    await self.ws_connection.ping()
                    self.log("心跳维持正常", debug=True)
                else:
                    self.log("连接已断开，停止心跳", error=True)
                    break
            except websockets.ConnectionClosed as e:
                self.log(f"连接异常关闭: {e.code} {e.reason}", error=True)
                break
            except Exception as e:
                self.log(f"心跳异常: {str(e)}", error=True)
                break

    async def process_message(self, message):
        """增强消息处理"""
        try:
            self.log(f"收到完整消息: {message}", debug=True)  # 显示完整消息
            data = json.loads(message)
            
            if data.get("op") == "block":
                await self.handle_block_data(data.get("x", {}))
            elif data.get("op") == "pong":
                self.log("收到心跳响应", debug=True)
            else:
                self.log(f"收到未知消息类型: {data.get('op')}", debug=True)
                
        except json.JSONDecodeError as e:
            self.log(f"消息解析失败: {str(e)}\n原始内容: {message[:200]}", error=True)
        except Exception as e:
            self.log(f"处理消息异常: {str(e)}", error=True)

    async def handle_block_data(self, block_data):
        """稳健的区块数据处理"""
        try:
            field_map = {
                'prev_block': ['prev_block', 'previousblockhash', 'prevBlockIndex'],
                'mrkl_root': ['mrkl_root', 'merkleroot', 'mrklRoot'],
                'nonce': ['nonce'],
                'bits': ['bits'],
                'version': ['version'],
                'time': ['time'],
                'height': ['height'],
                'hash': ['hash']
            }

            mapped_data = {}
            for target_field, possible_fields in field_map.items():
                for field in possible_fields:
                    if field in block_data:
                        value = block_data[field]
                        # 增强类型转换
                        if target_field in ['version', 'time', 'height', 'nonce', 'bits']:
                            try:
                                if isinstance(value, str) and value.startswith('0x'):
                                    mapped_data[target_field] = int(value, 16)
                                else:
                                    mapped_data[target_field] = int(float(value))
                            except Exception as e:
                                self.log(f"字段 {field} 转换失败: {value} → {str(e)}", error=True)
                                return
                        else:
                            mapped_data[target_field] = value
                        break
                else:
                    self.log(f"缺少必要字段: {target_field}", error=True)
                    return

            required_fields = ['hash', 'height', 'time', 'version', 'prev_block', 'mrkl_root', 'bits', 'nonce']
            if all(field in mapped_data for field in required_fields):
                receive_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                block_time = datetime.fromtimestamp(mapped_data['time']).strftime("%Y-%m-%d %H:%M:%S")
                
                self.root.after(0, self._update_ui, mapped_data, receive_time)
                self.write_to_file(mapped_data, receive_time, block_time)
                self.log(f"成功处理区块 #{mapped_data['height']}", debug=True)
            else:
                missing = [f for f in required_fields if f not in mapped_data]
                self.log(f"区块数据缺少必要字段: {missing}", error=True)

        except Exception as e:
            self.log(f"处理区块数据异常: {str(e)}\n{traceback.format_exc()}", error=True)

    def _update_ui(self, data, receive_time):
        """稳健UI更新"""
        try:
            self.info_text.delete(1.0, tk.END)
            info = (
                f"区块高度: {data['height']}\n"
                f"区块哈希: {data['hash']}\n"
                f"版本: 0x{data['version']:08x}\n"
                f"前导区块: {data['prev_block']}\n"
                f"默克尔根: {data['mrkl_root']}\n"
                f"时间戳: {datetime.fromtimestamp(data['time']).strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"难度目标: 0x{data['bits']:08x}\n"
                f"随机数: {data['nonce']}\n"
                f"本地接收时间: {receive_time}"
            )
            self.info_text.insert(tk.END, info)
            self.info_text.see(tk.END)
        except Exception as e:
            self.log(f"UI更新失败: {str(e)}\n{traceback.format_exc()}", error=True)

    async def handle_connection_error(self, error):
        """智能重连机制"""
        self.reconnect_attempts += 1
        self.current_endpoint = (self.current_endpoint + 1) % len(ENDPOINTS)
        
        wait_time = min(2 ** self.reconnect_attempts + random.uniform(0, 1), 60)
        self.log(f"连接异常: {str(error)}，{wait_time:.1f}秒后重试...")
        await asyncio.sleep(wait_time)

    async def cleanup_connection(self):
        """安全清理连接"""
        try:
            if self.ws_connection and not self.connection_closed():
                await self.ws_connection.close()
        except Exception as e:
            self.log(f"关闭连接时出错: {str(e)}", error=True)
        finally:
            self.connection_active = False
            self.ws_connection = None

    def write_to_file(self, block_data, receive_time, block_time):
        """增强文件写入"""
        try:
            log_line = (
                f"{block_data['hash']}|{block_data['height']}|"
                f"0x{block_data['version']:08x}|{block_data['prev_block']}|"
                f"{block_data['mrkl_root']}|{block_time}|"
                f"0x{block_data['bits']:08x}|{block_data['nonce']}|"
                f"{receive_time}\n"
            )
            with open(OUTPUT_FILE, "a") as f:
                f.write(log_line)
            self.log(f"成功写入日志: {log_line.strip()}", debug=True)
        except Exception as e:
            self.log(f"文件写入失败: {str(e)}", error=True)

    def log(self, message, error=False, debug=False):
        """增强日志记录"""
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log_type = '[ERROR] ' if error else '[DEBUG] ' if debug else ''
        log_entry = f"{timestamp} {log_type}{message}"
        
        self.log_area.insert(tk.END, log_entry + "\n")
        self.log_area.see(tk.END)
        
        try:
            with open(DEBUG_LOG, "a") as f:
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"日志写入失败: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = BlockchainMonitorGUI(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (asyncio.run(app.stop_monitoring()), root.destroy()))
    root.mainloop()

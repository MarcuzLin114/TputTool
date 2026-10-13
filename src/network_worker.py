import queue
import threading
import time
import subprocess
import os
import random
from datetime import datetime
from PyQt6.QtCore import QThread, pyqtSignal
from backend_functions import RawIcmpPing # 修正匯入
import logging
logger = logging.getLogger("HandoverTester.Worker")

import sys # 如果上方沒 import 到 sys，請確保有 import
def get_iperf_path():
    """動態計算 bin/iperf3 的執行檔路徑"""
    if getattr(sys, 'frozen', False):
        # PyInstaller 打包後執行：都在 _MEIPASS 的虛擬根目錄下
        base_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        iperf_dir = os.path.join(base_dir, "bin")
    else:
        # 開發階段執行：當前檔案位於 src/ 下，需回到上一層找 bin/
        current_dir = os.path.dirname(os.path.abspath(__file__))
        iperf_dir = os.path.join(current_dir, "..", "bin")

    iperf_name = "iperf3.exe" if os.name == "nt" else "iperf3"
    return os.path.normpath(os.path.join(iperf_dir, iperf_name))

def verify_iperf_version(iperf_path):
    """確認執行的 iperf3 版本為 3.21 (cJSON 1.7.15)"""
    if not os.path.exists(iperf_path):
        raise FileNotFoundError(f"找不到指定的 iperf3 執行檔: {iperf_path}")

    res = subprocess.run(
        [iperf_path, "-v"],
        capture_output=True,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    )
    version_output = res.stdout.strip()
    expected_version = "iperf 3.21 (cJSON 1.7.15)"
    
    if expected_version not in version_output:
        logger.error(f"iperf3 版本不符合！預期: '{expected_version}'，實際輸出:\n{version_output}")
        raise RuntimeError(f"iperf3 版本驗證失敗: 必須為 {expected_version}")
        
    logger.info(f"iperf3 版本驗證成功: {expected_version}")

class NetworkWorker(QThread):
    data_signal = pyqtSignal(float, float, float, str, str, str) 
    stat_signal = pyqtSignal(int, int, str, int)

    def __init__(self, config):
        super().__init__()
        self.cfg = config
        self.running = True
        self.ping_sent = 0
        self.ping_success = 0
        self.tshark_process = None
        self.pcap_path = ""
        self.ping_tool = RawIcmpPing()
        self.logical_sn = 0 

        # 判斷是否使用手動 ID
        if self.cfg.get('random_id') and self.cfg.get('icmp_id_in'):
            try:
                self.session_id = int(self.cfg['icmp_id_in'])
            except:
                self.session_id = random.randint(1, 65535)
        else:
            self.session_id = random.randint(1, 65535)
        
        logger.info(f"測試啟動，使用 ICMP ID: {self.session_id}")
    def enqueue_output(self, out, q):
        """專門負責讀取 stdout 的副執行緒函式"""
        try:
            for line in iter(out.readline, ''):
                if not self.running:
                    break
                if line:
                    q.put(line)
        except Exception as e:
            logger.error(f"Pipe 讀取執行緒異常: {e}")
        finally:
            out.close()


    def build_iperf_cmd(self):
        """根據前端配置動態構建 iperf3 指令"""
        cfg = self.cfg
        
        # 1. 取得專案內 bin 目錄下的 iperf3 路徑並驗證
        iperf_exe = get_iperf_path()
        verify_iperf_version(iperf_exe)

        # 2. 共同參數 (替換 "iperf3" 為 iperf_exe)
        cmd = [
            iperf_exe, 
            "-c", cfg['iperf_server'],
            "-p", cfg['iperf_port'],
            "-b", cfg['iperf_bw'],
            "-t", cfg['iperf_time'],
            "-i", cfg['interval'], # 【新增】讓 iperf 每隔幾秒輸出一次，對齊 Ping 間隔
            "--format", "m",
            "--forceflush"
        ]

        # 2. 協議特定參數
        if cfg.get('protocol') == "UDP":
            cmd.append("-u")
            if cfg.get('udp_len'):
                cmd.extend(["-l", cfg['udp_len']])
        else:
            # TCP 模式
            if cfg.get('tcp_parallel'):
                cmd.extend(["-P", cfg['tcp_parallel']])
            if cfg.get('tcp_window'):
                cmd.extend(["-w", cfg['tcp_window']])
            

        # 3. 模式參數 (正向/反向)
        if "反向" in cfg.get('mode', ''):
            cmd.append("-R")
            
        return cmd

    def run(self):
        # --- 加上這兩行修正命名 ---
        import threading
        threading.current_thread().name = "NetWorker"
        
        logger.info("網路測試執行緒啟動")
        start_time = time.time()
        self.iperf_process = None
        self.out_queue = queue.Queue() # 用來存放 iperf 輸出的佇列
        
        # --- 啟動 Wireshark 錄製 ---
        if self.cfg.get('use_wireshark'):
            # (原代碼不變...)
            self.pcap_path = f"Capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcapng"
            iface_id = self.cfg['wireshark_iface'].split('.')[0]
            tshark_cmd = ["tshark", "-i", iface_id, "-f", self.cfg['wireshark_filter'], "-w", self.pcap_path]
            self.tshark_process = subprocess.Popen(tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)

        # --- 啟動 iperf3 測試 ---
        if self.cfg.get('use_iperf'): 
            # 這裡呼叫 build_iperf_cmd 來動態生成指令
            iperf_cmd = self.build_iperf_cmd() 
            
            logger.debug(f"執行 iperf3 指令: {' '.join(iperf_cmd)}")
            
            self.iperf_process = subprocess.Popen(
                iperf_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True, 
                creationflags=subprocess.CREATE_NO_WINDOW,
                bufsize=1 # 行緩衝模式
            )
            
            # 啟動背景執行緒讀取 stdout，避免阻塞主迴圈
            self.read_thread = threading.Thread(
                target=self.enqueue_output, 
                args=(self.iperf_process.stdout, self.out_queue),
                daemon=True
            )
            self.read_thread.start()
        try:
            while self.running:
                # 獲取精確到毫秒的系統時間
                current_dt = datetime.now()
                now_ts = current_dt.strftime("%H:%M:%S.%f")[:-3]     # 用於 Console 顯示
                full_ts = current_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] # 用於存檔紀錄
                
                thru_val = 0.0
                iperf_display_logs = []
                lat = 0.0
                log_p = ""
                
                # --- 處理 iperf 輸出 ---
                has_sum_line = False
                temp_thru_val = 0.0

                while not self.out_queue.empty():
                    try:
                        line = self.out_queue.get_nowait().strip()
                        if line:
                            # 1. Console 顯示用的格式 (帶短時間標籤)
                            iperf_display_logs.append(f"[{now_ts}] {line}")
                            
                            # 2. 解析頻寬數值
                            if "Mbits/sec" in line:
                                parts = line.split()
                                if "Mbits/sec" in parts:
                                    current_val = float(parts[parts.index("Mbits/sec")-1])
                                    
                                    # 關鍵邏輯：如果有 [SUM] 行，優先採用 [SUM] 數據
                                    if "[SUM]" in line:
                                        thru_val = current_val
                                        has_sum_line = True
                                    elif not has_sum_line:
                                        # 如果還沒遇到 [SUM]，先拿一般行的數據當備用（單執行緒時使用）
                                        temp_thru_val = current_val
                    except Exception as e: 
                        logger.error(f"解析 iperf 行失敗: {e}")
                        break

                # 如果全部行讀完都沒有 [SUM]，說明是單執行緒(Pair=1)測試，採用備用數值
                if not has_sum_line and temp_thru_val > 0:
                    thru_val = temp_thru_val

                # --- 處理 Ping 輸出 ---
                if self.cfg.get('use_ping'):
                    self.logical_sn = (self.logical_sn + 1) % 65536
                    
                    # 1. 累加發送計數器 【關鍵修正】
                    self.ping_sent += 1  
                    
                    res = self.ping_tool.ping(self.cfg['ping_target'], self.session_id, self.logical_sn)
                    lat = float(res) if res is not None else 0.0
                    
                    # 2. 判斷是否成功，並累加成功計數器 【關鍵修正】
                    if res is not None:
                        self.ping_success += 1
                        log_p = f"[{now_ts}] ID:{self.session_id} SN:{self.logical_sn} Reply: {lat}ms"
                    else:
                        log_p = f"[{now_ts}] Timeout"
                
                # --- 發送數據 (新增傳遞 full_ts 用於存檔) ---

                if iperf_display_logs or log_p:
                    # 必須傳入 6 個參數，順序必須與 data_signal 定義一致
                    self.data_signal.emit(
                        time.time() - start_time,   # 1. 相對秒數 (float)
                        thru_val,                  # 2. 頻寬 (float)
                        lat,                       # 3. 延遲 (float)
                        "\n".join(iperf_display_logs), # 4. iperf Console 文字 (str)
                        log_p,                     # 5. Ping Console 文字 (str)
                        full_ts                    # 6. 新增：系統絕對時間戳 (str)
                    )
                
                time.sleep(float(self.cfg['interval']))


        finally:
            logger.info("正在關閉網路測試執行緒與清理進程")
            if self.iperf_process:
                self.iperf_process.terminate()
            if self.tshark_process:
                time.sleep(0.5)
                self.tshark_process.terminate()
            self.stat_signal.emit(self.ping_sent, self.ping_success, self.pcap_path, self.session_id)

    def stop(self): self.running = False
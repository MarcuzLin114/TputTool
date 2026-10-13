import queue
import threading
import time
import subprocess
import os
import random
from datetime import datetime
from PyQt6.QtCore import QThread, pyqtSignal
from backend_functions import RawIcmpPing
import logging
import sys

logger = logging.getLogger("HandoverTester.Worker")

def get_iperf_path():
    """取得 bin/iperf3 路徑"""
    if getattr(sys, 'frozen', False):
        base_dir = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        iperf_dir = os.path.join(base_dir, "bin")
    else:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        iperf_dir = os.path.join(current_dir, "..", "bin")
    iperf_name = "iperf3.exe" if os.name == "nt" else "iperf3"
    return os.path.normpath(os.path.join(iperf_dir, iperf_name))

def verify_iperf_version(iperf_path):
    """驗證 iperf3 版本"""
    if not os.path.exists(iperf_path):
        raise FileNotFoundError(f"找不到 iperf3 檔案: {iperf_path}")
    res = subprocess.run(
        [iperf_path, "-v"],
        capture_output=True,
        text=True,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    )
    version_output = res.stdout.strip()
    expected_version = "iperf 3.21 (cJSON 1.7.15)"
    if expected_version not in version_output:
        logger.error(f"iperf3 版本不符: 預期 '{expected_version}'，實際為:\n{version_output}")
        raise RuntimeError(f"iperf3 版本必須為 {expected_version}")
    logger.info(f"iperf3 版本驗證成功: {expected_version}")

class NetworkWorker(QThread):
    # 訊號發送: (經過秒數, 上行Mbps, 下行Mbps, 延遲ms, 上行Log, 下行Log, Ping Log, 系統時間戳)
    data_signal = pyqtSignal(float, float, float, float, str, str, str, str)
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
        
        # 進程管理
        self.ul_process = None
        self.dl_process = None
        self.ul_queue = queue.Queue()
        self.dl_queue = queue.Queue()

        if self.cfg.get('random_id') and self.cfg.get('icmp_id_in'):
            try:
                self.session_id = int(self.cfg['icmp_id_in'])
            except:
                self.session_id = random.randint(1, 65535)
        else:
            self.session_id = random.randint(1, 65535)
        logger.info(f"測試啟動，使用 ICMP ID: {self.session_id}")

    def enqueue_output(self, out, q):
        """讀取 process stdout 輸出並推入佇列"""
        try:
            for line in iter(out.readline, ''):
                if not self.running:
                    break
                if line:
                    q.put(line)
        except Exception as e:
            logger.error(f"Pipe 讀取中斷: {e}")
        finally:
            out.close()

    def build_iperf_cmd(self, port, bw, is_reverse=False):
        """建構單一方向的 iperf3 命令"""
        cfg = self.cfg
        iperf_exe = get_iperf_path()
        cmd = [
            iperf_exe,
            "-c", cfg['iperf_server'],
            "-p", str(port),
            "-t", str(cfg['iperf_time']),
            "-i", str(cfg['interval']),
            "--format", "m",
            "--forceflush"
        ]

        # 2. 只有在頻寬有填寫時才帶入 -b；若為 TCP 且留空則完全不帶 -b
        bw_str = str(bw).strip() if bw is not None else ""
        if bw_str:
            cmd.extend(["-b", bw_str])
        elif cfg.get('protocol') == "UDP":
            # UDP 若留空，帶入預設 1M 避免發送端過載
            cmd.extend(["-b", "1M"])

        bind_ip = cfg.get('iperf_bind_ip', '').strip()
        if bind_ip:
            cmd.extend(["-B", bind_ip])

        if cfg.get('protocol') == "UDP":
            cmd.append("-u")
            if cfg.get('udp_len'):
                cmd.extend(["-l", cfg['udp_len']])
        else:
            if cfg.get('tcp_parallel'):
                cmd.extend(["-P", cfg['tcp_parallel']])
            if cfg.get('tcp_window'):
                cmd.extend(["-w", cfg['tcp_window']])

        if is_reverse:
            cmd.append("-R")

        return cmd

    def parse_iperf_queue(self, q, now_ts):
        """自 Queue 中解析該秒吞吐量數值與收集輸出日誌"""
        thru_val = 0.0
        display_logs = []
        has_sum_line = False
        temp_thru_val = 0.0

        while not q.empty():
            try:
                line = q.get_nowait().strip()
                if line:
                    display_logs.append(f"[{now_ts}] {line}")
                    if "Mbits/sec" in line:
                        parts = line.split()
                        if "Mbits/sec" in parts:
                            idx = parts.index("Mbits/sec")
                            try:
                                current_val = float(parts[idx - 1])
                                if "[SUM]" in line:
                                    thru_val = current_val
                                    has_sum_line = True
                                elif not has_sum_line:
                                    temp_thru_val = current_val
                            except (ValueError, IndexError):
                                pass
            except Exception:
                break

        if not has_sum_line and temp_thru_val > 0:
            thru_val = temp_thru_val

        return thru_val, display_logs

    def run(self):
        threading.current_thread().name = "NetWorker"
        logger.info("網路測試執行緒啟動")
        start_time = time.time()

        # 1. 啟動 Wireshark / TShark 抓包
        if self.cfg.get('use_wireshark'):
            self.pcap_path = f"Capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcapng"
            iface_id = self.cfg['wireshark_iface'].split('.')[0]
            tshark_cmd = ["tshark", "-i", iface_id, "-f", self.cfg['wireshark_filter'], "-w", self.pcap_path]
            self.tshark_process = subprocess.Popen(
                tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

        # 2. 啟動 iperf3 進程
        if self.cfg.get('use_iperf'):
            iperf_exe = get_iperf_path()
            verify_iperf_version(iperf_exe)
            mode = self.cfg.get('mode', '')

            # 上行進程
            if "上行" in mode or "Simultaneous" in mode or "雙向" in mode:
                ul_cmd = self.build_iperf_cmd(
                    port=self.cfg['iperf_ul_port'],
                    bw=self.cfg['iperf_ul_bw'],
                    is_reverse=False
                )
                logger.debug(f"執行 iperf3 上行指令: {' '.join(ul_cmd)}")
                self.ul_process = subprocess.Popen(
                    ul_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, creationflags=subprocess.CREATE_NO_WINDOW, bufsize=1
                )
                threading.Thread(target=self.enqueue_output, args=(self.ul_process.stdout, self.ul_queue), daemon=True).start()

            # 下行進程
            if "下行" in mode or "Simultaneous" in mode or "雙向" in mode:
                dl_cmd = self.build_iperf_cmd(
                    port=self.cfg['iperf_dl_port'],
                    bw=self.cfg['iperf_dl_bw'],
                    is_reverse=True
                )
                logger.debug(f"執行 iperf3 下行指令: {' '.join(dl_cmd)}")
                self.dl_process = subprocess.Popen(
                    dl_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, creationflags=subprocess.CREATE_NO_WINDOW, bufsize=1
                )
                threading.Thread(target=self.enqueue_output, args=(self.dl_process.stdout, self.dl_queue), daemon=True).start()

        # 3. 每秒同步採樣循環
        try:
            while self.running:
                current_dt = datetime.now()
                now_ts = current_dt.strftime("%H:%M:%S.%f")[:-3]
                full_ts = current_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

                thru_ul, ul_logs = self.parse_iperf_queue(self.ul_queue, now_ts)
                thru_dl, dl_logs = self.parse_iperf_queue(self.dl_queue, now_ts)

                # Ping 採樣
                lat = 0.0
                log_p = ""
                if self.cfg.get('use_ping'):
                    self.logical_sn = (self.logical_sn + 1) % 65536
                    self.ping_sent += 1
                    res = self.ping_tool.ping(self.cfg['ping_target'], self.session_id, self.logical_sn)
                    lat = float(res) if res is not None else 0.0
                    if res is not None:
                        self.ping_success += 1
                        log_p = f"[{now_ts}] ID:{self.session_id} SN:{self.logical_sn} Reply: {lat}ms"
                    else:
                        log_p = f"[{now_ts}] Timeout"

                # 每秒同步發送數據訊號
                if ul_logs or dl_logs or log_p:
                    self.data_signal.emit(
                        time.time() - start_time,
                        thru_ul,
                        thru_dl,
                        lat,
                        "\n".join(ul_logs),
                        "\n".join(dl_logs),
                        log_p,
                        full_ts
                    )

                time.sleep(float(self.cfg['interval']))
        finally:
            logger.info("正在關閉網路測試執行緒與清理進程")
            if self.ul_process:
                self.ul_process.terminate()
            if self.dl_process:
                self.dl_process.terminate()
            if self.tshark_process:
                time.sleep(0.5)
                self.tshark_process.terminate()
            self.stat_signal.emit(self.ping_sent, self.ping_success, self.pcap_path, self.session_id)

    def stop(self):
        self.running = False
import time
import subprocess
import socket
import struct
import logging
import os
import tarfile
import shutil
import tempfile
from datetime import datetime

# 配置日誌
logger = logging.getLogger("HandoverTester.Backend")

# 定義上傳的目標網路芳鄰路徑
TARGET_PATH = os.path.join(r"\\10.255.175.166", "Verification", "Charter", "Charter_OTA_Log")


class RawIcmpPing:
    def __init__(self):
        # 注意：Raw Socket 在 Windows 上必須以管理員權限執行
        try:
            self.icmp_proto = socket.getprotobyname("icmp")
        except socket.error:
            self.icmp_proto = None

    def checksum(self, source_string):
        """修正後的網路標準 Checksum 計算"""
        sum = 0
        # 若長度為奇數，補一個 null byte
        if len(source_string) % 2 == 1:
            source_string += b'\x00'
            
        for i in range(0, len(source_string), 2):
            # 讀取兩個位元組並組成 16-bit 字值
            word = (source_string[i] << 8) + source_string[i + 1]
            sum += word
            
        # 將進位部分加回低位
        sum = (sum >> 16) + (sum & 0xffff)
        sum += (sum >> 16)
        
        # 取反碼並只保留 16-bit
        answer = ~sum & 0xffff
        return answer

    def ping(self, ip_addr, icmp_id, sequence_num, timeout=1):
        if self.icmp_proto is None:
            return "Error: Protocol initialization failed"
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.icmp_proto)
        except PermissionError:
            return "Error: Admin rights required"
        
        # 修正後的 ping 方法內部邏輯
        # 1. 構造初始標頭 (Checksum 為 0)
        header = struct.pack(">BBHHH", 8, 0, 0, icmp_id, sequence_num)
        data = b"RawPingData"

        # 2. 計算包含 Data 的 Checksum
        my_checksum = self.checksum(header + data)

        # 3. 重新封裝，將計算出的 Checksum 放入
        header = struct.pack(">BBHHH", 8, 0, my_checksum, icmp_id, sequence_num)
        packet = header + data

        try:
            send_time = time.perf_counter()
            my_socket.sendto(packet, (ip_addr, 1))
            my_socket.settimeout(timeout)
            recv_packet, addr = my_socket.recvfrom(1024)
            recv_time = time.perf_counter()
            return round((recv_time - send_time) * 1000, 2)
        except socket.timeout:
            return None
        finally:
            my_socket.close()


def run_tshark_analysis(pcap_path, target_id, start_time_str=None):
    """利用 TShark 分析指定 Session ID 的 ICMP 數量，支援起始時間軸對齊"""
    try:
        filter_req = f"icmp.type==8 && icmp.ident=={target_id}"
        filter_rep = f"icmp.type==0 && icmp.ident=={target_id}"
        
        # 💡 若有傳入第一筆時間軸，掛上 TShark 絕對時間過濾條件（格式: "YYYY-MM-DD HH:MM:SS.mmm"）
        if start_time_str:
            filter_req += f" && frame.time >= \"{start_time_str}\""
            filter_rep += f" && frame.time >= \"{start_time_str}\""
            
        cmd_req = ["tshark", "-r", pcap_path, "-Y", filter_req, "-T", "fields", "-e", "frame.number"]
        req_out = subprocess.run(cmd_req, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW).stdout
        count_req = len(req_out.strip().split('\n')) if req_out.strip() else 0
        
        cmd_rep = ["tshark", "-r", pcap_path, "-Y", filter_rep, "-T", "fields", "-e", "frame.number"]
        rep_out = subprocess.run(cmd_rep, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW).stdout
        count_rep = len(rep_out.strip().split('\n')) if rep_out.strip() else 0
        
        return count_req, count_rep
    except Exception as e:
        return 0, 0

def run_iperf_tshark_analysis(pcap_path, port, protocol, start_time_str=None):
    """透過 TShark 分析 iperf 損耗，支援起始時間軸對齊"""
    try:
        if protocol.upper() == "TCP":
            filter_total = f"tcp.port == {port}"
            filter_retr = f"tcp.port == {port} && tcp.analysis.retransmission"
            
            if start_time_str:
                filter_total += f" && frame.time >= \"{start_time_str}\""
                filter_retr += f" && frame.time >= \"{start_time_str}\""
                
            cmd_total = ["tshark", "-r", pcap_path, "-Y", filter_total, "-T", "fields", "-e", "frame.number"]
            out_total = subprocess.run(cmd_total, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW).stdout
            total_pkts = len(out_total.strip().split('\n')) if out_total.strip() else 0
            
            cmd_retr = ["tshark", "-r", pcap_path, "-Y", filter_retr, "-T", "fields", "-e", "frame.number"]
            out_retr = subprocess.run(cmd_retr, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW).stdout
            retr_pkts = len(out_retr.strip().split('\n')) if out_retr.strip() else 0
            
            loss_rate = (retr_pkts / total_pkts * 100) if total_pkts > 0 else 0.0
            return total_pkts, retr_pkts, loss_rate
            
        elif protocol.upper() == "UDP":
            filter_total = f"udp.port == {port}"
            filter_seq = f"udp.port == {port} && iperf3.seq"
            
            if start_time_str:
                filter_total += f" && frame.time >= \"{start_time_str}\""
                filter_seq += f" && frame.time >= \"{start_time_str}\""
                
            cmd_total = ["tshark", "-r", pcap_path, "-Y", filter_total, "-T", "fields", "-e", "frame.number"]
            out_total = subprocess.run(cmd_total, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW).stdout
            received_pkts = len(out_total.strip().split('\n')) if out_total.strip() else 0
            
            cmd_seq = ["tshark", "-r", pcap_path, "-Y", filter_seq, "-T", "fields", "-e", "iperf3.seq"]
            out_seq = subprocess.run(cmd_seq, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW).stdout
            
            if out_seq.strip():
                seq_list = [int(x) for x in out_seq.strip().split('\n') if x.strip().isdigit()]
                if seq_list:
                    seq_min, seq_max = min(seq_list), max(seq_list)
                    expected_pkts = seq_max - seq_min + 1
                    lost_pkts = max(0, expected_pkts - len(set(seq_list)))
                    loss_rate = (lost_pkts / expected_pkts * 100) if expected_pkts > 0 else 0.0
                    return expected_pkts, lost_pkts, loss_rate
            
            return received_pkts, 0, 0.0
    except Exception as e:
        print(f"分析 iperf TShark 失敗: {e}")
        return 0, 0, 0.0

def generate_filename(note: str) -> str:
    """產生成果壓縮檔檔名 (格式: YYYYMMDD_HHMMSS_UE_Side_LOG_備註)"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{ts}_UE_Side_LOG"
    note = note.strip()
    if note:
        base = f"{base}_{note}"
    return base


def resolve_target_name(directory: str, base_name: str) -> str:
    """處理遠端資料夾檔名衝突，若重複則自動加上序號後綴"""
    if not os.path.exists(os.path.join(directory, f"{base_name}.tar.gz")):
        return f"{base_name}.tar.gz"
    n = 1
    while True:
        new_name = f"{base_name}_{n}.tar.gz"
        if not os.path.exists(os.path.join(directory, new_name)):
            return new_name
        n += 1


def silent_pack_and_upload(file_paths, note="Auto_HO_Automation"):
    """
    將指定的檔案清單打包成 .tar.gz 並異步上傳至遠端網路芳鄰路徑
    
    :param file_paths: 包含要上傳的檔案路徑清單 (例如: Excel, XML, pcapng, log)
    :param note: 壓縮檔檔名的自訂備註後綴
    :return: (bool 成功與否, str 遠端產生的壓縮檔名或錯誤訊息)
    """
    tmp_dir = tempfile.mkdtemp()
    base_name = generate_filename(note)
    archive_path = os.path.join(tmp_dir, f"{base_name}.tar.gz")

    try:
        # 建立本地暫存壓縮檔並打包所有存在的 Log 檔案
        with tarfile.open(archive_path, "w:gz") as tar:
            for path in file_paths:
                if os.path.exists(path):
                    tar.add(path, arcname=os.path.basename(path))

        # 檢查遠端網路芳鄰路徑是否可用
        if not os.path.isdir(TARGET_PATH):
            return False, f"無法連線至網路芳鄰目標路徑。檔案暫存於: {archive_path}"

        # 確定最終遠端不重複的檔名與路徑
        final_name = resolve_target_name(TARGET_PATH, base_name)
        dest_path = os.path.join(TARGET_PATH, final_name)
        
        # 複製至網路芳鄰目標資料夾
        shutil.copy2(archive_path, dest_path)
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return True, final_name

    except Exception as exc:
        return False, str(exc)

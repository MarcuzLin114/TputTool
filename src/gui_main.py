import json
import sys
import os
import time
from datetime import datetime  
import pandas as pd
import numpy as np
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, 
                             QPushButton, QHBoxLayout, QLineEdit, QLabel, 
                             QGridLayout, QCheckBox, QTextEdit, QGroupBox, QComboBox, QTabWidget,
                             QFileDialog, QInputDialog)  # <-- 在這裡新增 QFileDialog, QInputDialog
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIntValidator
import pyqtgraph as pg

# 匯入自定義模組
from network_worker import NetworkWorker
from backend_functions import run_tshark_analysis # 修正匯入


import logging

# 配置日誌格式
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] (%(threadName)-10s) %(message)s',
    handlers=[
        logging.FileHandler("app_debug.log", encoding='utf-8'), # 寫入檔案
        logging.StreamHandler() # 同步輸出到終端機
    ]
)
logger = logging.getLogger("HandoverTester")

class HandoverTester(QMainWindow):
    CONFIG_FILE = "last_settings.json"
    def __init__(self):
        super().__init__()
        self.setWindowTitle("5G Handover Analyzer v2.0 (Modular)")
        self.resize(1300, 1100)
        self.test_data = []
        self.worker = None
        self.init_ui()
        self.load_last_settings() # 啟動時載入上次記錄

    def get_interfaces(self):
        """抓取 TShark 網卡清單"""
        import subprocess
        try:
            result = subprocess.run(
                ["tshark", "-D"], capture_output=True, text=True, 
                encoding='utf-8', errors='replace', creationflags=subprocess.CREATE_NO_WINDOW
            )
            lines = result.stdout.strip().split('\n')
            return lines if lines != [''] else ["1. 無法偵測網卡"]
        except:
            return ["1. 錯誤: 未安裝或找不到 TShark"]

    def find_active_interface_index(self, interfaces):
        """透過 PowerShell 自動尋找當前分配有實體 IPv4 且連線中的網卡 GUID，並與 TShark 清單比對 (免疫中文編碼問題)"""
        import subprocess
        try:
            # 💡 核心修正：改撈取實體有分配 IP 網卡的 InterfaceGUID (例如: {076B91D6-...})
            cmd = [
                "powershell", "-Command", 
                "Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*'} | Get-NetAdapter | Select-Object -ExpandProperty InterfaceGUID"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW)
            active_guids = [line.strip().lower() for line in res.stdout.strip().split('\n') if line.strip()]
            
            # 走訪所有當前作用中的 GUID
            for guid in active_guids:
                # 去除大括號，做更具彈性的不分大小寫子字串比對
                clean_guid = guid.replace("{", "").replace("}", "").strip()
                if not clean_guid:
                    continue
                    
                for idx, iface in enumerate(interfaces):
                    # TShark 的描述內一定會包含該網卡的實體 GUID 碼
                    if clean_guid in iface.lower():
                        return idx
        except Exception as e:
            logger.error(f"自動偵測使用中網卡失敗: {e}")
        return None

    def init_ui(self):
        cw = QWidget()
        self.setCentralWidget(cw)
        main_layout = QVBoxLayout(cw)

        # --- 1. 功能與模式設定 ---
        top_group = QGroupBox("功能與模式設定")
        top_layout = QHBoxLayout()
        self.chk_iperf = QCheckBox("啟用 iperf3")
        self.chk_ping = QCheckBox("啟用 Ping"); self.chk_ping.setChecked(True)
        self.chk_auto_upload = QCheckBox("測試結束自動上傳數據")  # <-- 新增：自動上傳開關
        self.chk_auto_upload.setChecked(True) # 預設開啟
        self.mode_sel = QComboBox(); self.mode_sel.addItems(["正向 (Uplink)", "反向 (Downlink)", "雙向 (Simultaneous)"])
        
        top_layout.addWidget(self.chk_iperf)
        top_layout.addWidget(self.chk_ping)
        top_layout.addWidget(self.chk_auto_upload)  # <-- 新增：加入佈局
        top_layout.addWidget(QLabel("模式:"))
        top_layout.addWidget(self.mode_sel)
        top_group.setLayout(top_layout)
        main_layout.addWidget(top_group)

        # --- 2. Wireshark 錄製設定 ---
        ws_group = QGroupBox("Wireshark / TShark 錄製設定")
        ws_layout = QGridLayout()
        self.chk_ws = QCheckBox("啟動封裝錄製與分析"); self.chk_ws.setChecked(True)
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(self.get_interfaces())
        self.filter_in = QLineEdit("")
        
        ws_layout.addWidget(self.chk_ws, 0, 0)
        ws_layout.addWidget(QLabel("選擇網卡:"), 0, 1); ws_layout.addWidget(self.iface_combo, 0, 2)
        ws_layout.addWidget(QLabel("捕獲過濾器:"), 0, 3); ws_layout.addWidget(self.filter_in, 0, 4)
        ws_group.setLayout(ws_layout)
        main_layout.addWidget(ws_group)
        
        # --- 3. 測試參數配置 ---
        param_group = QGroupBox("測試參數配置")
        param_main_layout = QHBoxLayout() # 使用橫向佈局來切分左右兩邊

        # --- 3a. iperf3 參數區 ---
        # --- iperf3 測試設定群組 ---
        iperf_group = QGroupBox("iperf3 測試設定")
        iperf_layout = QVBoxLayout()  # 垂直佈局作為主容器

        # 1. 共同參數區 (QGridLayout)
        common_layout = QGridLayout()
        self.iperf_server = QLineEdit("10.255.174.125")
        self.iperf_port = QLineEdit("55023")
        self.iperf_bw = QLineEdit("1M")      # 共同參數 -b
        self.iperf_time = QLineEdit("3600")   # 共同參數 -t
        
        common_layout.addWidget(QLabel("伺服器 IP (-c):"), 0, 0)
        common_layout.addWidget(self.iperf_server, 0, 1)
        common_layout.addWidget(QLabel("連接埠 (-p):"), 0, 2)
        common_layout.addWidget(self.iperf_port, 0, 3)
        common_layout.addWidget(QLabel("目標頻寬 (-b):"), 1, 0)
        common_layout.addWidget(self.iperf_bw, 1, 1)
        common_layout.addWidget(QLabel("測試時間 (-t):"), 1, 2)
        common_layout.addWidget(self.iperf_time, 1, 3)
        
        iperf_layout.addLayout(common_layout) # 加入主容器

        # 2. 協議切換分頁 (QTabWidget)
        self.proto_tabs = QTabWidget()
        
        # TCP 分頁
        tcp_widget = QWidget()
        tcp_form = QGridLayout(tcp_widget)
        self.tcp_parallel = QLineEdit("1")
        self.tcp_window = QLineEdit("64KB")
        tcp_form.addWidget(QLabel("執行緒數 (-P):"), 0, 0)
        tcp_form.addWidget(self.tcp_parallel, 0, 1)
        tcp_form.addWidget(QLabel("視窗大小 (-w):"), 0, 2)
        tcp_form.addWidget(self.tcp_window, 0, 3)
        
        # UDP 分頁
        udp_widget = QWidget()
        udp_form = QGridLayout(udp_widget)
        self.udp_len = QLineEdit("1450")
        udp_form.addWidget(QLabel("緩衝區長度 (-l):"), 0, 0)
        udp_form.addWidget(self.udp_len, 0, 1)
        
        self.proto_tabs.addTab(tcp_widget, "TCP 模式")
        self.proto_tabs.addTab(udp_widget, "UDP 模式")
        
        iperf_layout.addWidget(self.proto_tabs) # 加入主容器

        # --- 重點修正處 ---
        iperf_group.setLayout(iperf_layout) # 必須呼叫 setLayout 才能正常渲染
        main_layout.addWidget(iperf_group)  # 將整個 GroupBox 加入主視窗佈局

        # --- 3b. Ping 參數區 ---
        ping_subgroup = QGroupBox("Ping (延遲測試)")
        ping_grid = QGridLayout()
        ping_grid.addWidget(QLabel("Ping 目標:"), 0, 0)
        self.ping_target = QLineEdit("10.255.253.254")
        ping_grid.addWidget(self.ping_target, 0, 1)

        ping_grid.addWidget(QLabel("發送間隔 (s):"), 1, 0)
        self.ping_targetterval = QLineEdit("1")
        ping_grid.addWidget(self.ping_targetterval, 1, 1)
    


        # --- 3b. Ping 參數區 ---
        ping_subgroup = QGroupBox("Ping (延遲測試)")
        ping_main_vbox = QVBoxLayout() # 必須建立一個 Layout 給 GroupBox

        ping_grid = QGridLayout()
        ping_grid.addWidget(QLabel("Ping 目標:"), 0, 0)
        self.ping_target = QLineEdit("10.255.253.254")
        ping_grid.addWidget(self.ping_target, 0, 1)

        ping_grid.addWidget(QLabel("發送間隔 (s):"), 1, 0)
        self.ping_targetterval = QLineEdit("1")
        ping_grid.addWidget(self.ping_targetterval, 1, 1)
        ping_main_vbox.addLayout(ping_grid)

        # ICMP ID 手動設定區塊
        icmp_id_layout = QHBoxLayout()
        self.chk_custom_icmp_id = QCheckBox("手動設定 ICMP ID")
        self.chk_custom_icmp_id.setChecked(False)

        self.icmp_id_in = QLineEdit() # 名稱統一改為 icmp_id_in 避免混淆
        self.icmp_id_in.setPlaceholderText("ID (0-65535)")
        self.icmp_id_in.setValidator(QIntValidator(0, 65535))
        self.icmp_id_in.setEnabled(False) 

        # 連動邏輯：勾選後才可輸入
        self.chk_custom_icmp_id.toggled.connect(self.icmp_id_in.setEnabled)

        icmp_id_layout.addWidget(self.chk_custom_icmp_id)
        icmp_id_layout.addWidget(self.icmp_id_in)
        ping_main_vbox.addLayout(icmp_id_layout)
        
        ping_main_vbox.addStretch()
        ping_subgroup.setLayout(ping_main_vbox) # 設定 GroupBox 的主佈局

        # 將子區塊加入主要參數佈局
        param_main_layout.addWidget(iperf_group, 2) # iperf 權重佔 2
        param_main_layout.addWidget(ping_subgroup, 1)  # ping 權重佔 1
        param_group.setLayout(param_main_layout)
        
        main_layout.addWidget(param_group)

        # --- 4. 統計摘要與控制按鈕 ---
        self.lbl_stats = QLabel("Session Summary: 等待測試中..."); self.lbl_stats.setStyleSheet("background:#222; color:#0F0; padding:10px; font-weight:bold;")
        main_layout.addWidget(self.lbl_stats)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("開始測試 (START)"); self.start_btn.setFixedHeight(40); self.start_btn.clicked.connect(self.start_test)
        self.stop_btn = QPushButton("停止測試 (STOP)"); self.stop_btn.setFixedHeight(40); self.stop_btn.setEnabled(False); self.stop_btn.clicked.connect(self.stop_test)
        
        # <-- 新增：手動上傳按鈕
        self.manual_upload_btn = QPushButton("手動打包上傳檔案 (MANUAL UPLOAD)")
        self.manual_upload_btn.setFixedHeight(40)
        self.manual_upload_btn.clicked.connect(self.manual_upload)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.manual_upload_btn)  # <-- 新增：加入佈局
        main_layout.addLayout(btn_layout)

        # --- 5. 即時圖表區 ---
        self.plot_widget = pg.GraphicsLayoutWidget()
        main_layout.addWidget(self.plot_widget, 6)
        self.setup_plots()

        # --- 6. Terminal Console ---
        tl = QHBoxLayout()
        self.iperf_cons = QTextEdit(); self.ping_cons = QTextEdit()
        for c in [self.iperf_cons, self.ping_cons]: 
            c.setReadOnly(True)
            c.setStyleSheet("background:#000; color:#0F0; font-family:Consolas; font-size:9pt;")
        tl.addWidget(self.iperf_cons); tl.addWidget(self.ping_cons)
        main_layout.addLayout(tl, 2)

    def save_current_settings(self):
        """將當前 UI 上的參數儲存至 JSON 檔案"""
        settings = {
            "iperf_server": self.iperf_server.text(),
            "iperf_port": self.iperf_port.text(),
            "iperf_bw": self.iperf_bw.text(),
            "iperf_time": self.iperf_time.text(),
            "tcp_parallel": self.tcp_parallel.text(),
            "tcp_window": self.tcp_window.text(),
            "udp_len": self.udp_len.text(),
            "ping_target": self.ping_target.text(),
            "ping_targetterval": self.ping_targetterval.text(),
            "use_iperf": self.chk_iperf.isChecked(),
            "use_ping": self.chk_ping.isChecked(),
            "use_wireshark": self.chk_ws.isChecked(),
            "chk_custom_icmp_id": self.chk_custom_icmp_id.isChecked(),
            "icmp_id_in_value": self.icmp_id_in.text(),
            "auto_upload": self.chk_auto_upload.isChecked(),  # <-- 新增記憶狀態
            "ws_iface_index": self.iface_combo.currentIndex(), # <-- 🛠️ 補上儲存網卡
            "filter_in": self.filter_in.text(),                 # <-- 🛠️ 補上儲存過濾器
        }
        try:
            with open(self.CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            print(f"儲存設定失敗: {e}")

    def load_last_settings(self):
        """從 JSON 檔案載入參數並更新 UI"""
        if not os.path.exists(self.CONFIG_FILE):
            return
        
        try:
            with open(self.CONFIG_FILE, "r", encoding="utf-8") as f:
                s = json.load(f)
                
            self.iperf_server.setText(s.get("iperf_server", "10.255.253.254"))
            self.iperf_port.setText(s.get("iperf_port", "55000"))
            self.iperf_bw.setText(s.get("iperf_bw", "20M")) 
            self.iperf_time.setText(s.get("iperf_time", "3600")) 
            self.tcp_parallel.setText(s.get("tcp_parallel", "4"))
            self.tcp_window.setText(s.get("tcp_window", "4"))
            self.udp_len.setText(s.get("udp_len", "1450"))
            self.ping_target.setText(s.get("ping_target", "10.255.253.254"))
            self.ping_targetterval.setText(s.get("ping_targetterval", "1"))
            self.chk_iperf.setChecked(s.get("use_iperf", True))
            self.chk_ping.setChecked(s.get("use_ping", True))
            self.chk_ws.setChecked(s.get("use_wireshark", False))
            # 修正：QLineEdit 使用 setText 而非 setChecked
            self.chk_custom_icmp_id.setChecked(s.get("chk_custom_icmp_id", False))
            self.icmp_id_in.setText(s.get("icmp_id_in_value", "")) 
            self.icmp_id_in.setEnabled(self.chk_custom_icmp_id.isChecked()) # 同步啟用狀態
            self.filter_in.setText(s.get("filter_in", ""))

            # <-- 新增恢復勾選狀態
            self.chk_auto_upload.setChecked(s.get("auto_upload", True))
            self.filter_in.setText(s.get("filter_in", ""))

            # ─── 🛠️ 【修改處：優先使用智慧自動偵測，無果才帶入歷史紀錄】 ───
            iface_list = [self.iface_combo.itemText(i) for i in range(self.iface_combo.count())]
            active_idx = self.find_active_interface_index(iface_list)
            
            if active_idx is not None:
                self.iface_combo.setCurrentIndex(active_idx)
                logger.info(f"啟動智慧引導：已自動切換至當前作用中網卡索引 [{active_idx}]")
            else:
                iface_idx = s.get("ws_iface_index", 0)
                if iface_idx < self.iface_combo.count():
                    self.iface_combo.setCurrentIndex(iface_idx)

        except Exception as e:
            print(f"載入設定失敗: {e}")

    def setup_plots(self):
        """配置即時繪圖組件"""
        self.p1 = self.plot_widget.addPlot(title="Throughput (Mbps)"); self.c1 = self.p1.plot(pen='g'); self.p1.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.nextRow()
        self.p2 = self.plot_widget.addPlot(title="Latency (ms)"); self.s2 = pg.ScatterPlotItem(size=5, brush='r'); self.p2.addItem(self.s2); self.p2.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.nextRow()
        self.p3 = self.plot_widget.addPlot(title="Full Session History"); self.p3.showGrid(x=True, y=True, alpha=0.3)
        self.c3t = self.p3.plot(pen='g')
        self.p3v2 = pg.ViewBox(); self.p3.scene().addItem(self.p3v2)
        self.p3.getAxis('right').linkToView(self.p3v2); self.p3v2.setXLink(self.p3)
        self.c3p = pg.PlotDataItem(pen=pg.mkPen('r', style=Qt.PenStyle.DotLine))
        self.p3v2.addItem(self.c3p)
        self.p3.getViewBox().sigResized.connect(lambda: self.p3v2.setGeometry(self.p3.getViewBox().sceneBoundingRect()))

    def start_test(self):
        # 在測試開始前儲存當前參數
        self.save_current_settings()
        """啟動測試執行緒"""
        self.start_datetime = datetime.now() # <-- 【新增】記錄精確的開始測試時間
        self.test_data = []; self.iperf_cons.clear(); self.ping_cons.clear()
        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        
        config = {
            'use_iperf': self.chk_iperf.isChecked(),
            'use_ping': self.chk_ping.isChecked(),
            'random_id': self.chk_custom_icmp_id.isChecked(),
            'icmp_id_in': self.icmp_id_in.text(), 
            'use_wireshark': self.chk_ws.isChecked(),
            'wireshark_iface': self.iface_combo.currentText(),
            'wireshark_filter': self.filter_in.text(),
            'ping_target': self.ping_target.text(),
            'interval': self.ping_targetterval.text(),
            'mode': self.mode_sel.currentText(),
            'iperf_server': self.iperf_server.text(),
            'iperf_port': self.iperf_port.text(),
            'iperf_bw': self.iperf_bw.text(), 
            'iperf_time': self.iperf_time.text(), 
            'protocol': "UDP" if self.proto_tabs.currentIndex() == 1 else "TCP",
            'udp_len': self.udp_len.text(),
            'tcp_parallel': self.tcp_parallel.text(),
            'tcp_window': self.tcp_window.text(),
        }
        
        self.worker = NetworkWorker(config)
        self.worker.data_signal.connect(self.handle_data)
        self.worker.stat_signal.connect(self.handle_final_stats)
        self.worker.start()

    def handle_data(self, elapsed, thru, lat, i_raw, p_raw, sys_ts):
        if i_raw: self.iperf_cons.append(i_raw)
        if p_raw: self.ping_cons.append(p_raw)
        
        # 儲存原始數據，此時包含 float 與 str
        self.test_data.append([round(elapsed, 2), thru, lat, sys_ts])
        
        if elapsed > 0:
            try:
                # 建立一個暫時的 numpy 陣列用於計算，只取前三欄並指定為 float
                all_d_numeric = np.array([row[:3] for row in self.test_data], dtype=float)
                
                t_avg = np.mean(all_d_numeric[:, 1])
                # 延遲平均值排除 0 (Timeout) 的情況
                l_avg = np.mean(all_d_numeric[all_d_numeric[:, 2] > 0, 2]) if any(all_d_numeric[:, 2] > 0) else 0
                
                # ─── 🛠️ 【修改處：根據 iperf3 勾選狀態決定頻寬文字】 ───
                if self.chk_iperf.isChecked():
                    thru_str = f"{t_avg:.1f} Mbps"
                else:
                    thru_str = "N/A"
                
                self.lbl_stats.setText(f"即時摘要 - 平均頻寬: {thru_str} | 平均延遲: {l_avg:.1f} ms")
                # ───────────────────────────────────────────────────
                
                # 更新圖表使用的是 all_d_numeric，這保證了繪圖數據全是數值
                window = all_d_numeric[-100:]
                self.c1.setData(window[:, 0], window[:, 1])
                self.s2.setData(x=window[:, 0], y=window[:, 2])
                self.c3t.setData(all_d_numeric[:, 0], all_d_numeric[:, 1])
                self.c3p.setData(all_d_numeric[:, 0], all_d_numeric[:, 2])
                self.p3v2.setGeometry(self.p3.getViewBox().sceneBoundingRect())
            except Exception as e:
                logger.error(f"數據更新錯誤: {e}")


    def handle_final_stats(self, sent, success, pcap_path, session_id):
        # 💡 核心修正：獲取 Handover_Report 的第一筆絕對時間軸字串
        report_start_time_str = None
        if hasattr(self, 'current_df') and not self.current_df.empty:
            report_start_time_str = self.current_df['System_Timestamp'].iloc[0] # 例如: "2026-07-03 17:18:48.641"[cite: 5]

        # 💡 A. 【ICMP 軟體層】依據 Report 起始時間軸重新計算
        if hasattr(self, 'current_df') and not self.current_df.empty and self.chk_ping.isChecked():
            aligned_sent = len(self.current_df)
            aligned_success = len(self.current_df[self.current_df['Latency_ms'].astype(float) > 0])
            sw_loss_rate = ((aligned_sent - aligned_success) / aligned_sent * 100) if aligned_sent > 0 else 0.0
            icmp_sw_report = f"【軟體層】發送: {aligned_sent}, 成功: {aligned_success}, 掉包率: {sw_loss_rate:.2f}%"
        else:
            sw_loss_rate = ((sent - success) / sent * 100) if sent > 0 else 0
            icmp_sw_report = f"【軟體層】發送: {sent}, 成功: {success}, 掉包率: {sw_loss_rate:.2f}%"
            
        report = f"\n--- [測試結束統計報告] ---\n{icmp_sw_report}\n"

        # 💡 B. 【ICMP 封包層】傳入 report_start_time_str 進行剪裁對齊[cite: 19]
        if pcap_path and os.path.exists(pcap_path):
            self.ping_cons.append(f"> 正在分析 Session 0x{session_id:04x} (對齊時間軸)...")
            QApplication.processEvents()
            # 傳入對齊時間軸參數
            req, rep = run_tshark_analysis(pcap_path, session_id, start_time_str=report_start_time_str)
            p_loss = req - rep
            
            if req > 0:
                p_rate = (p_loss / req * 100)
            else:
                p_rate = 100.00 if (hasattr(self, 'current_df') and len(self.current_df) > 0) else 0.00
                
            icmp_p_report = f"【封包層】捕捉 Request: {req}, Reply: {rep}, 掉包率: {p_rate:.2f}%"
            report += f"{icmp_p_report}\n"
            
            if hasattr(self, 'generated_files'):
                self.generated_files.append(pcap_path)
        else:
            p_rate = 100.00 if (hasattr(self, 'current_df') and len(self.current_df) > 0) else 0.00
            icmp_p_report = f"【封包層】捕捉 Request: 0, Reply: 0, 掉包率: {p_rate:.2f}%"
            report += f"{icmp_p_report}\n"
        
        # 💡 C. 【iperf3 軟體層與封包層】同步套用 report_start_time_str 進行剪裁對齊[cite: 19]
        iperf_sw_report = "N/A"
        iperf_p_report = "N/A"
        
        if self.chk_iperf.isChecked():
            iperf_port = self.iperf_port.text()
            proto = "UDP" if self.proto_tabs.currentIndex() == 1 else "TCP"
            
            if hasattr(self, 'current_df'):
                valid_intervals = len(self.current_df)
                # 排除 N/A 的情況計算真實平均頻寬
                clean_thru = self.current_df[self.current_df['Throughput_Mbps'] != "N/A"]['Throughput_Mbps'].astype(float)
                avg_thru_val = clean_thru.mean() if not clean_thru.empty else 0.0
                
                # 軟體層統計
                iperf_sent_intervals = valid_intervals
                iperf_succ_intervals = len(clean_thru[clean_thru > 0])
                iperf_sw_loss = ((iperf_sent_intervals - iperf_succ_intervals) / iperf_sent_intervals * 100) if iperf_sent_intervals > 0 else 0.0
                iperf_sw_report = f"【軟體層】發送: {iperf_sent_intervals}, 成功: {iperf_succ_intervals}, 掉包率: {iperf_sw_loss:.2f}%"
            
            if pcap_path and os.path.exists(pcap_path):
                from backend_functions import run_iperf_tshark_analysis
                # 傳入對齊時間軸參數
                total_or_expected, issue_pkts, iperf_loss_rate = run_iperf_tshark_analysis(pcap_path, iperf_port, proto, start_time_str=report_start_time_str)
                
                if proto == "TCP":
                    iperf_p_report = f"【封包層】總捕捉封包: {total_or_expected}, 重傳封包: {issue_pkts}, 掉包率(重傳率): {iperf_loss_rate:.2f}%"
                else:
                    iperf_p_report = f"【封包層】捕捉 Request: {total_or_expected}, Reply: {total_or_expected - issue_pkts}, 掉包率: {iperf_loss_rate:.2f}%"
            else:
                iperf_p_report = "【封包層】未偵測到 Capture 封包檔案"

        report += f"iperf3 統計數據:\n{iperf_sw_report}\n{iperf_p_report}\n"
        self.ping_cons.append(report)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        # 💡 D. 導出完全對齊格式的最終 Summary Report[cite: 19]
        if hasattr(self, 'current_df') and self.current_df is not None:
            df = self.current_df
            try:
                ping_data = df['Latency_ms'].astype(float)
                valid_ping = ping_data[ping_data > 0]
                max_lat = valid_ping.max() if not valid_ping.empty else 0.0
                min_lat = valid_ping.min() if not valid_ping.empty else 0.0
                avg_lat = valid_ping.mean() if not valid_ping.empty else 0.0
                
                if self.chk_iperf.isChecked():
                    thru_data = df['Throughput_Mbps'].astype(float)
                    max_thru = thru_data.max() if not thru_data.empty else 0.0
                    min_thru = thru_data.min() if not thru_data.empty else 0.0
                    avg_thru = thru_data.mean() if not thru_data.empty else 0.0
                else:
                    max_thru, min_thru, avg_thru = "N/A", "N/A", "N/A"
                    
                mode_text = self.mode_sel.currentText()
                if "反向" in mode_text or "Downlink" in mode_text:
                    ul_max, ul_min, ul_avg = "N/A", "N/A", "N/A"
                    dl_max, dl_min, dl_avg = max_thru, min_thru, avg_thru
                else:
                    ul_max, ul_min, ul_avg = max_thru, min_thru, avg_thru
                    dl_max, dl_min, dl_avg = "N/A", "N/A", "N/A"
                    
                start_time_dt = getattr(self, 'start_time_dt', datetime.now())
                end_time_dt = getattr(self, 'end_time_dt', datetime.now())
                total_duration_sec = getattr(self, 'total_duration_sec', 0.0)
                file_id = getattr(self, 'file_id', int(time.time()))
                summary_path = f"Handover_Summary_{file_id}.xlsx"
                
                import socket
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("10.255.255.255", 1))
                    src_ip = s.getsockname()[0]
                    s.close()
                except:
                    src_ip = "Unknown"
                    
                proto = "UDP" if self.proto_tabs.currentIndex() == 1 else "TCP"
                
                summary_data = {
                    "測試統計/資訊項目": [
                        "開始測試時間", "結束測試時間", "總測試時間 (秒)",
                        "來源端 IP (Source IP)", "目的端 IP (Ping Target)", "目的端 IP (iperf Server)",
                        "ICMP 測試參數", "Interval", "SessionID",
                        "ICMP 軟體層掉包率", "ICMP 封包層掉包率",  
                        "iperf 測試參數", "Port:", "BW:", "TargetTime:", "Protocol:", "Parallel:", "Window:",
                        "iperf 軟體層掉包率", "iperf 封包層掉包率",  
                        "iperf 版本",
                        "Ping 最大延遲 (ms)", "Ping 最小延遲 (ms)", "Ping 平均延遲 (ms)",
                        "上行最大流量 (Uplink Max Mbps)", "上行最小流量 (Uplink Min Mbps)", "上行平均流量 (Uplink Avg Mbps)",
                        "下行最大流量 (Downlink Max Mbps)", "下行最小流量 (Downlink Min Mbps)", "下行平均流量 (Downlink Avg Mbps)"
                    ],
                    "數值與組態內容": [
                        start_time_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        end_time_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        round(total_duration_sec, 2),
                        src_ip,
                        self.ping_target.text(),
                        self.iperf_server.text(),
                        "", f"{self.ping_targetterval.text()}s", session_id,
                        icmp_sw_report, icmp_p_report,
                        "", self.iperf_port.text(), self.iperf_bw.text(), f"{self.iperf_time.text()}s", proto,
                        self.tcp_parallel.text() if proto == "TCP" else "N/A", self.tcp_window.text() if proto == "TCP" else "N/A",
                        iperf_sw_report, iperf_p_report,
                        "iperf 3.x (iperf3)",
                        round(max_lat, 2) if isinstance(max_lat, (int, float)) else max_lat,
                        round(min_lat, 2) if isinstance(min_lat, (int, float)) else min_lat,
                        round(avg_lat, 2) if isinstance(avg_lat, (int, float)) else avg_lat,
                        round(ul_max, 2) if isinstance(ul_max, (int, float)) else ul_max,
                        round(ul_min, 2) if isinstance(ul_min, (int, float)) else ul_min,
                        round(ul_avg, 2) if isinstance(ul_avg, (int, float)) else ul_avg,
                        round(dl_max, 2) if isinstance(dl_max, (int, float)) else dl_max,
                        round(dl_min, 2) if isinstance(dl_min, (int, float)) else dl_min,
                        round(dl_avg, 2) if isinstance(dl_avg, (int, float)) else dl_avg
                    ]
                }
                df_summary = pd.DataFrame(summary_data)
                df_summary.to_excel(summary_path, index=False)
                self.generated_files.append(summary_path)
                logger.info(f"摘要統計報表已成功獨立生成: {summary_path}")
            except Exception as e:
                logger.error(f"摘要統計報表導出失敗: {e}")

        # ─── 【自動傳輸遠端網路芳鄰機制】 ───
        if hasattr(self, 'generated_files') and self.chk_auto_upload.isChecked():
            self.ping_cons.append("> [自動化機制] 正在自動將對齊後的日誌檔案上傳至目標網路芳鄰...")
            import threading
            from backend_functions import silent_pack_and_upload
            threading.Thread(target=lambda: silent_pack_and_upload(self.generated_files, note="Auto_HO_Automation"), daemon=True).start()


    def stop_test(self):
        if self.worker:
            self.worker.stop()
            self.end_time_dt = datetime.now() # 【新增】將時間戳記錄為執行緒屬性
            self.start_time_dt = getattr(self, 'start_datetime', self.end_time_dt)
            self.total_duration_sec = (self.end_time_dt - self.start_time_dt).total_seconds()
            
            self.generated_files = [] # 用于儲存本次測試產生的所有檔案路徑
            
            if self.test_data:
                # 建立 DataFrame
                df = pd.DataFrame(self.test_data, columns=[
                    'Relative_Time_s', 
                    'Throughput_Mbps', 
                    'Latency_ms', 
                    'System_Timestamp'
                ])
                
                # 依據 iperf3 起始數據為主，動態清洗對齊數據
                if self.chk_iperf.isChecked():
                    nonzero_thru = df[df['Throughput_Mbps'] > 0]
                    if not nonzero_thru.empty:
                        first_valid_idx = nonzero_thru.index[0]
                        df = df.loc[first_valid_idx:].reset_index(drop=True)
                        
                        if not df.empty:
                            df['Relative_Time_s'] = round(df['Relative_Time_s'] - df['Relative_Time_s'].iloc[0], 2)
                            try:
                                self.start_time_dt = datetime.strptime(df['System_Timestamp'].iloc[0], "%Y-%m-%d %H:%M:%S.%f")
                                self.total_duration_sec = (self.end_time_dt - self.start_time_dt).total_seconds()
                            except Exception as e:
                                logger.error(f"重新解析起始時間戳失敗: {e}")
                else:
                    df['Throughput_Mbps'] = "N/A"

                self.file_id = int(time.time())
                xlsx_path = f"Handover_Report_{self.file_id}.xlsx"
                
                # 1. 導出原始逐秒資料 Excel
                df.to_excel(xlsx_path, index=False)
                self.generated_files.append(xlsx_path)
                
                # 暫存清洗後的 df 供後續 handle_final_stats 生成摘要報表使用
                self.current_df = df


    def manual_upload(self):
        """功能2：手動選擇檔案、壓縮並上傳"""
        # 1. 彈出檔案選擇視窗 (支援複選)
        files, _ = QFileDialog.getOpenFileNames(
            self, 
            "手動選擇檔案上傳", 
            "", 
            "All Files (*);;Excel Files (*.xlsx);;XML Files (*.xml);;Log Files (*.log *.pcapng)"
        )
        
        if not files:
            return  # 使用者沒選檔案就直接離開
            
        # 2. 彈出輸入對話框讓使用者寫備註說明 (選填)
        note, ok = QInputDialog.getText(
            self, 
            "手動上傳備註", 
            "請輸入壓縮檔名備註說明（選填）：", 
            text="Manual_Upload"
        )
        
        if not ok:
            return  # 如果點擊「取消」則中止上傳流程
            
        self.ping_cons.append(f"> [手動上傳] 正在打包並上傳選取的 {len(files)} 個檔案...")
        
        import threading
        from backend_functions import silent_pack_and_upload

        # 背景線程：執行壓縮包裝與傳輸任務，避免 GUI 卡死
        def bg_manual_upload_worker(files_list, upload_note):
            success, result_msg = silent_pack_and_upload(files_list, note=upload_note)
            if success:
                logger.info(f"手動上傳成功: {result_msg}")
                self.ping_cons.append(f"【手動上傳成功】遠端壓縮檔名: {result_msg}\n")
            else:
                logger.error(f"手動上傳失敗: {result_msg}")
                self.ping_cons.append(f"【手動上傳失敗】原因: {result_msg}\n")

        threading.Thread(target=bg_manual_upload_worker, args=(files, note), daemon=True).start()

# gui_main.py 片段 
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = HandoverTester()
    win.show()
    sys.exit(app.exec())
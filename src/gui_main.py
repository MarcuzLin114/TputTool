import json
import sys
import os
import time
import shutil
import socket
import logging  # <-- 移至最上方 import
from datetime import datetime

import pandas as pd
import numpy as np
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget,
                             QPushButton, QHBoxLayout, QLineEdit, QLabel,
                             QGridLayout, QCheckBox, QTextEdit, QGroupBox, QComboBox, QTabWidget,
                             QFileDialog, QInputDialog)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIntValidator
import pyqtgraph as pg
from network_worker import NetworkWorker
from backend_functions import run_tshark_analysis

# 判斷是打包環境還是源碼環境
if getattr(sys, 'frozen', False):
    APP_ROOT = os.path.dirname(sys.executable)
else:
    APP_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from logging.handlers import RotatingFileHandler  # <-- 引入 RotatingFileHandler

# 設定日誌
LOG_DIR = os.path.join(APP_ROOT, "log")
os.makedirs(LOG_DIR, exist_ok=True)

logging_config = {
    'level': logging.DEBUG,
    'format': '%(asctime)s [%(levelname)s] (%(threadName)-10s) %(message)s',
    'handlers': [
        # 當 app_debug.log 大於 1MB 時自動分割為 app_debug.log.1, app_debug.log.2 ...
        RotatingFileHandler(
            os.path.join(LOG_DIR, "app_debug.log"),
            maxBytes=1 * 1024 * 1024,
            backupCount=20,
            encoding='utf-8'
        ),
        logging.StreamHandler()
    ]
}

logging.basicConfig(**logging_config)
logger = logging.getLogger("HandoverTester")

class HandoverTester(QMainWindow):
    CONFIG_FILE = os.path.join(APP_ROOT, "last_settings.json")

    def __init__(self):
        super().__init__()
        self.setWindowTitle("5G Handover Analyzer v2.0 (Modular)")
        self.resize(1300, 1100)
        self.test_data = []
        self.worker = None
        self.init_ui()
        self.load_last_settings()

    def get_local_ipv4_interfaces(self):
        """獲取本機所有網卡名稱與對應的 IPv4 位址"""
        iface_items = [("自動 (Default Route)", "")]
        try:
            import psutil
            for nic_name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        iface_items.append((f"{nic_name} ({addr.address})", addr.address))
        except Exception as e:
            logger.error(f"獲取本機網卡失敗: {e}")
        return iface_items

    def get_interfaces(self):
        """獲取 TShark 網卡列表"""
        import subprocess
        try:
            result = subprocess.run(
                ["tshark", "-D"], capture_output=True, text=True,
                encoding='utf-8', errors='replace', creationflags=subprocess.CREATE_NO_WINDOW
            )
            lines = result.stdout.strip().split('\n')
            return lines if lines != [''] else ["1. 找不到任何可用介面"]
        except:
            return ["1. 系統未安裝 TShark"]

    def find_active_interface_index(self, interfaces):
        """智慧引導網卡"""
        import subprocess
        try:
            cmd = [
                "powershell", "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*'} | Get-NetAdapter | Select-Object -ExpandProperty InterfaceGUID"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW)
            active_guids = [line.strip().lower() for line in res.stdout.strip().split('\n') if line.strip()]

            for guid in active_guids:
                clean_guid = guid.replace("{", "").replace("}", "").strip()
                if not clean_guid:
                    continue
                for idx, iface in enumerate(interfaces):
                    if clean_guid in iface.lower():
                        return idx
        except Exception as e:
            logger.error(f"網卡自動識別失敗: {e}")
        return None

    def init_ui(self):
        cw = QWidget()
        self.setCentralWidget(cw)
        main_layout = QVBoxLayout(cw)

        # --- 1. 功能模式設定 ---
        top_group = QGroupBox("功能與模式設定")
        top_layout = QHBoxLayout()
        self.chk_iperf = QCheckBox("啟用 iperf3")
        self.chk_ping = QCheckBox("啟用 Ping"); self.chk_ping.setChecked(True)
        self.chk_auto_upload = QCheckBox("測試結束自動上傳數據")
        self.chk_auto_upload.setChecked(False)
        self.mode_sel = QComboBox()
        self.mode_sel.addItems(["雙向 (Simultaneous)", "上行 (Uplink)", "下行 (Downlink)"])
        self.mode_sel.currentIndexChanged.connect(self.on_mode_changed)

        top_layout.addWidget(self.chk_iperf)
        top_layout.addWidget(self.chk_ping)
        top_layout.addWidget(self.chk_auto_upload)
        top_layout.addWidget(QLabel("模式:"))
        top_layout.addWidget(self.mode_sel)
        top_group.setLayout(top_layout)
        main_layout.addWidget(top_group)

        # --- 2. Wireshark 設定 ---
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
        param_main_layout = QHBoxLayout()

        # --- 3a. iperf3 設定 (支援雙組上下行參數) ---
        iperf_group = QGroupBox("iperf3 測試設定")
        iperf_layout = QVBoxLayout()

        common_layout = QGridLayout()
        self.iperf_server = QLineEdit("192.168.111.10")
        self.iperf_time = QLineEdit("3600")

        self.iperf_bind_combo = QComboBox()
        self.iperf_bind_combo.setEditable(True)
        for label, ip in self.get_local_ipv4_interfaces():
            self.iperf_bind_combo.addItem(label, ip)

        common_layout.addWidget(QLabel("伺服器 IP (-c):"), 0, 0)
        common_layout.addWidget(self.iperf_server, 0, 1)
        common_layout.addWidget(QLabel("測試時間 (-t):"), 0, 2)
        common_layout.addWidget(self.iperf_time, 0, 3)

        common_layout.addWidget(QLabel("指定介面 (-B):"), 1, 0)
        common_layout.addWidget(self.iperf_bind_combo, 1, 1, 1, 3)

        # 上行與下行獨立參數
        self.iperf_ul_port = QLineEdit("54000")
        self.iperf_ul_bw = QLineEdit("1M")
        self.iperf_ul_bw.setPlaceholderText("留空為不限速")
        self.iperf_dl_port = QLineEdit("54001")
        self.iperf_dl_bw = QLineEdit("1M")
        self.iperf_dl_bw.setPlaceholderText("留空為不限速")

        common_layout.addWidget(QLabel("上行埠 (-p):"), 2, 0)
        common_layout.addWidget(self.iperf_ul_port, 2, 1)
        common_layout.addWidget(QLabel("上行頻寬 (-b):"), 2, 2)
        common_layout.addWidget(self.iperf_ul_bw, 2, 3)

        common_layout.addWidget(QLabel("下行埠 (-p):"), 3, 0)
        common_layout.addWidget(self.iperf_dl_port, 3, 1)
        common_layout.addWidget(QLabel("下行頻寬 (-b):"), 3, 2)
        common_layout.addWidget(self.iperf_dl_bw, 3, 3)

        iperf_layout.addLayout(common_layout)

        # 協定分頁
        self.proto_tabs = QTabWidget()
        tcp_widget = QWidget()
        tcp_form = QGridLayout(tcp_widget)
        self.tcp_parallel = QLineEdit("6")
        self.tcp_window = QLineEdit("64KB")
        tcp_form.addWidget(QLabel("執行緒數 (-P):"), 0, 0)
        tcp_form.addWidget(self.tcp_parallel, 0, 1)
        tcp_form.addWidget(QLabel("視窗大小 (-w):"), 0, 2)
        tcp_form.addWidget(self.tcp_window, 0, 3)

        udp_widget = QWidget()
        udp_form = QGridLayout(udp_widget)
        self.udp_len = QLineEdit("1450")
        udp_form.addWidget(QLabel("封包長度 (-l):"), 0, 0)
        udp_form.addWidget(self.udp_len, 0, 1)

        self.proto_tabs.addTab(tcp_widget, "TCP 模式")
        self.proto_tabs.addTab(udp_widget, "UDP 模式")
        iperf_layout.addWidget(self.proto_tabs)
        iperf_group.setLayout(iperf_layout)

        # --- 3b. Ping 設定 ---
        ping_subgroup = QGroupBox("Ping (延遲測試)")
        ping_main_vbox = QVBoxLayout()
        ping_grid = QGridLayout()
        ping_grid.addWidget(QLabel("Ping 目標:"), 0, 0)
        self.ping_target = QLineEdit("192.168.111.10")
        ping_grid.addWidget(self.ping_target, 0, 1)
        ping_grid.addWidget(QLabel("發送間隔 (s):"), 1, 0)
        self.ping_targetterval = QLineEdit("1")
        ping_grid.addWidget(self.ping_targetterval, 1, 1)

        # [新增] Ping 指定介面下拉選單
        self.ping_bind_combo = QComboBox()
        self.ping_bind_combo.setEditable(True)
        for label, ip in self.get_local_ipv4_interfaces():
            self.ping_bind_combo.addItem(label, ip)
        ping_grid.addWidget(QLabel("指定介面:"), 2, 0)
        ping_grid.addWidget(self.ping_bind_combo, 2, 1)

        ping_main_vbox.addLayout(ping_grid)

        icmp_id_layout = QHBoxLayout()
        self.chk_custom_icmp_id = QCheckBox("手動設定 ICMP ID")
        self.chk_custom_icmp_id.setChecked(False)
        self.icmp_id_in = QLineEdit()
        self.icmp_id_in.setPlaceholderText("ID (0-65535)")
        self.icmp_id_in.setValidator(QIntValidator(0, 65535))
        self.icmp_id_in.setEnabled(False)
        self.chk_custom_icmp_id.toggled.connect(self.icmp_id_in.setEnabled)
        icmp_id_layout.addWidget(self.chk_custom_icmp_id)
        icmp_id_layout.addWidget(self.icmp_id_in)
        ping_main_vbox.addLayout(icmp_id_layout)
        ping_main_vbox.addStretch()
        ping_subgroup.setLayout(ping_main_vbox)

        param_main_layout.addWidget(iperf_group, 2)
        param_main_layout.addWidget(ping_subgroup, 1)
        param_group.setLayout(param_main_layout)
        main_layout.addWidget(param_group)

        # --- 4. 即時摘要與控制按鈕 ---
        self.lbl_stats = QLabel("即時摘要 - 上行: 0.0 Mbps | 下行: 0.0 Mbps | 平均延遲: 0.0 ms")
        self.lbl_stats.setStyleSheet("background:#222; color:#0F0; padding:10px; font-weight:bold;")
        main_layout.addWidget(self.lbl_stats)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("開始測試 (START)"); self.start_btn.setFixedHeight(40); self.start_btn.clicked.connect(self.start_test)
        self.stop_btn = QPushButton("停止測試 (STOP)"); self.stop_btn.setFixedHeight(40); self.stop_btn.setEnabled(False); self.stop_btn.clicked.connect(self.stop_test)
        self.manual_upload_btn = QPushButton("手動打包上傳檔案 (MANUAL UPLOAD)")
        self.manual_upload_btn.setFixedHeight(40)
        self.manual_upload_btn.clicked.connect(self.manual_upload)

        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.manual_upload_btn)
        main_layout.addLayout(btn_layout)

        # --- 5. 圖表區 (Throughput 同時顯示上下行) ---
        self.plot_widget = pg.GraphicsLayoutWidget()
        main_layout.addWidget(self.plot_widget, 6)
        self.setup_plots()

        # --- 6. Terminal Console (分頁呈現上下行流量數據) ---
        tl = QHBoxLayout()
        self.iperf_tabs = QTabWidget()
        self.iperf_ul_cons = QTextEdit()
        self.iperf_dl_cons = QTextEdit()
        for c in [self.iperf_ul_cons, self.iperf_dl_cons]:
            c.setReadOnly(True)
            c.setStyleSheet("background:#000; color:#0F0; font-family:Consolas; font-size:9pt;")
        self.iperf_tabs.addTab(self.iperf_ul_cons, "上行流量 (Uplink)")
        self.iperf_tabs.addTab(self.iperf_dl_cons, "下行流量 (Downlink)")

        self.ping_cons = QTextEdit()
        self.ping_cons.setReadOnly(True)
        self.ping_cons.setStyleSheet("background:#000; color:#0F0; font-family:Consolas; font-size:9pt;")

        tl.addWidget(self.iperf_tabs, 3)
        tl.addWidget(self.ping_cons, 2)
        main_layout.addLayout(tl, 2)

    def on_mode_changed(self):
        """依據所選模式動態啟用/停用上下行參數欄位"""
        mode = self.mode_sel.currentText()
        is_bi = "雙向" in mode or "Simultaneous" in mode
        is_ul = "上行" in mode or "Uplink" in mode
        is_dl = "下行" in mode or "Downlink" in mode

        self.iperf_ul_port.setEnabled(is_bi or is_ul)
        self.iperf_ul_bw.setEnabled(is_bi or is_ul)
        self.iperf_dl_port.setEnabled(is_bi or is_dl)
        self.iperf_dl_bw.setEnabled(is_bi or is_dl)

    def setup_plots(self):
        """配置 pyqtgraph 圖表，支援上下行雙線與圖例"""
        # 1. 吞吐量圖表 (UL 綠線, DL 青線)
        self.p1 = self.plot_widget.addPlot(title="Throughput (Mbps)")
        self.p1.addLegend(offset=(10, 10))
        self.c1_ul = self.p1.plot(pen=pg.mkPen('g', width=2), name="上行 (UL)")
        self.c1_dl = self.p1.plot(pen=pg.mkPen('c', width=2), name="下行 (DL)")
        self.p1.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.nextRow()

        # 2. 延遲圖表
        self.p2 = self.plot_widget.addPlot(title="Latency (ms)")
        self.s2 = pg.ScatterPlotItem(size=5, brush='r')
        self.p2.addItem(self.s2)
        self.p2.showGrid(x=True, y=True, alpha=0.3)
        self.plot_widget.nextRow()

        # 3. 完整歷程圖表
        self.p3 = self.plot_widget.addPlot(title="Full Session History")
        self.p3.addLegend(offset=(10, 10))
        self.c3_ul = self.p3.plot(pen=pg.mkPen('g', width=1.5), name="上行 (UL)")
        self.c3_dl = self.p3.plot(pen=pg.mkPen('c', width=1.5), name="下行 (DL)")
        self.p3.showGrid(x=True, y=True, alpha=0.3)

        self.p3v2 = pg.ViewBox()
        self.p3.scene().addItem(self.p3v2)
        self.p3.getAxis('right').linkToView(self.p3v2)
        self.p3v2.setXLink(self.p3)
        self.c3p = pg.PlotDataItem(pen=pg.mkPen('r', style=Qt.PenStyle.DotLine))
        self.p3v2.addItem(self.c3p)
        self.p3.getViewBox().sigResized.connect(lambda: self.p3v2.setGeometry(self.p3.getViewBox().sceneBoundingRect()))

    def save_current_settings(self):
        settings = {
            "iperf_server": self.iperf_server.text(),
            "iperf_ul_port": self.iperf_ul_port.text(),
            "iperf_ul_bw": self.iperf_ul_bw.text(),
            "iperf_dl_port": self.iperf_dl_port.text(),
            "iperf_dl_bw": self.iperf_dl_bw.text(),
            "iperf_time": self.iperf_time.text(),
            "tcp_parallel": self.tcp_parallel.text(),
            "tcp_window": self.tcp_window.text(),
            "udp_len": self.udp_len.text(),
            "ping_target": self.ping_target.text(),
            "ping_targetterval": self.ping_targetterval.text(),
            "ping_bind_ip": self.ping_bind_combo.currentText(),
            "use_iperf": self.chk_iperf.isChecked(),
            "use_ping": self.chk_ping.isChecked(),
            "use_wireshark": self.chk_ws.isChecked(),
            "chk_custom_icmp_id": self.chk_custom_icmp_id.isChecked(),
            "iperf_bind_ip": self.iperf_bind_combo.currentText(),
            "icmp_id_in_value": self.icmp_id_in.text(),
            "auto_upload": self.chk_auto_upload.isChecked(),
            "mode_index": self.mode_sel.currentIndex(),
            "ws_iface_index": self.iface_combo.currentIndex(),
            "filter_in": self.filter_in.text(),
        }
        try:
            with open(self.CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            print(f"儲存設定檔失敗: {e}")

    def load_last_settings(self):
        if not os.path.exists(self.CONFIG_FILE):
            return
        try:
            with open(self.CONFIG_FILE, "r", encoding="utf-8") as f:
                s = json.load(f)
            self.iperf_server.setText(s.get("iperf_server", "192.168.111.10"))
            self.iperf_ul_port.setText(s.get("iperf_ul_port", s.get("iperf_port", "54000")))
            self.iperf_ul_bw.setText(s.get("iperf_ul_bw", s.get("iperf_bw", "1M")))
            self.iperf_dl_port.setText(s.get("iperf_dl_port", "54001"))
            self.iperf_dl_bw.setText(s.get("iperf_dl_bw", "1M"))
            self.iperf_time.setText(s.get("iperf_time", "3600"))
            self.tcp_parallel.setText(s.get("tcp_parallel", "6"))
            self.tcp_window.setText(s.get("tcp_window", "64KB"))
            self.udp_len.setText(s.get("udp_len", "1450"))
            self.ping_target.setText(s.get("ping_target", "192.168.111.10"))
            self.ping_targetterval.setText(s.get("ping_targetterval", "1"))
            self.chk_iperf.setChecked(s.get("use_iperf", True))
            self.chk_ping.setChecked(s.get("use_ping", True))
            self.chk_ws.setChecked(s.get("use_wireshark", True))
            self.chk_custom_icmp_id.setChecked(s.get("chk_custom_icmp_id", False))
            self.icmp_id_in.setText(s.get("icmp_id_in_value", ""))
            self.icmp_id_in.setEnabled(self.chk_custom_icmp_id.isChecked())
            self.filter_in.setText(s.get("filter_in", ""))
            self.chk_auto_upload.setChecked(s.get("auto_upload", False))
            self.mode_sel.setCurrentIndex(s.get("mode_index", 0))

            iface_list = [self.iface_combo.itemText(i) for i in range(self.iface_combo.count())]
            active_idx = self.find_active_interface_index(iface_list)
            if active_idx is not None:
                self.iface_combo.setCurrentIndex(active_idx)
            else:
                iface_idx = s.get("ws_iface_index", 0)
                if iface_idx < self.iface_combo.count():
                    self.iface_combo.setCurrentIndex(iface_idx)

            saved_bind = s.get("iperf_bind_ip", "")
            if saved_bind:
                idx = self.iperf_bind_combo.findText(saved_bind)
                if idx >= 0:
                    self.iperf_bind_combo.setCurrentIndex(idx)
                else:
                    self.iperf_bind_combo.setCurrentText(saved_bind)

            self.on_mode_changed()

            saved_ping_bind = s.get("ping_bind_ip", "")
            if saved_ping_bind:
                idx = self.ping_bind_combo.findText(saved_ping_bind)
                if idx >= 0:
                    self.ping_bind_combo.setCurrentIndex(idx)
                else:
                    self.ping_bind_combo.setCurrentText(saved_ping_bind)
        except Exception as e:
            print(f"讀取設定檔失敗: {e}")

    def start_test(self):
        self.save_current_settings()
        self.start_datetime = datetime.now()
        self.current_session_folder = self.start_datetime.strftime("%Y%m%d_%H%M%S")

        # ==================== [新增] 初始化 1MB 數據分卷機制 ====================
        # 取得當次測試專屬目錄路徑
        self.session_dir = os.path.join(LOG_DIR, self.current_session_folder)
        os.makedirs(self.session_dir, exist_ok=True)
        
        self.log_file_index = 1
        self.current_csv_path = os.path.join(
            self.session_dir, f"Handover_Data_{self.log_file_index:03d}.csv"
        )
        
        # 建立首個分卷檔案並寫入標頭 (Header)
        self.csv_headers = [
            'Relative_Time_s',
            'UL_Throughput_Mbps',
            'DL_Throughput_Mbps',
            'Latency_ms',
            'System_Timestamp'
        ]
        with open(self.current_csv_path, 'w', encoding='utf-8-sig') as f:
            f.write(','.join(self.csv_headers) + '\n')
            
        self.all_session_csv_files = [self.current_csv_path]
        # =====================================================================

        self.test_data = []
        self.iperf_ul_cons.clear()
        self.iperf_dl_cons.clear()
        self.ping_cons.clear()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        selected_ip = self.iperf_bind_combo.currentData()
        if not selected_ip:
            typed = self.iperf_bind_combo.currentText().strip()
            selected_ip = typed if typed and "自動" not in typed and "Default" not in typed else ""

        self.current_test_bind_ip = selected_ip if selected_ip else "Auto (Default)"

        # 解析 Ping 指定網卡 IP
        selected_ping_ip = self.ping_bind_combo.currentData()
        if not selected_ping_ip:
            typed = self.ping_bind_combo.currentText().strip()
            selected_ping_ip = typed if typed and "自動" not in typed and "Default" not in typed else ""
        self.current_test_ping_bind_ip = selected_ping_ip if selected_ping_ip else "Auto (Default)"

        config = {
            'use_iperf': self.chk_iperf.isChecked(),
            'use_ping': self.chk_ping.isChecked(),
            'random_id': self.chk_custom_icmp_id.isChecked(),
            'icmp_id_in': self.icmp_id_in.text(),
            'use_wireshark': self.chk_ws.isChecked(),
            'wireshark_iface': self.iface_combo.currentText(),
            'wireshark_filter': self.filter_in.text(),
            'ping_target': self.ping_target.text(),
            'ping_bind_ip': selected_ping_ip,  # <-- [新增] 傳入 Ping 綁定 IP
            'interval': self.ping_targetterval.text(),
            'mode': self.mode_sel.currentText(),
            'iperf_server': self.iperf_server.text(),
            'iperf_ul_port': self.iperf_ul_port.text(),
            'iperf_ul_bw': self.iperf_ul_bw.text(),
            'iperf_dl_port': self.iperf_dl_port.text(),
            'iperf_dl_bw': self.iperf_dl_bw.text(),
            'iperf_time': self.iperf_time.text(),
            'iperf_bind_ip': selected_ip,
            'protocol': "UDP" if self.proto_tabs.currentIndex() == 1 else "TCP",
            'udp_len': self.udp_len.text(),
            'tcp_parallel': self.tcp_parallel.text(),
            'tcp_window': self.tcp_window.text(),
        }

        self.worker = NetworkWorker(config)
        self.worker.data_signal.connect(self.handle_data)
        self.worker.stat_signal.connect(self.handle_final_stats)
        self.worker.start()

    def handle_data(self, elapsed, thru_ul, thru_dl, lat, ul_raw, dl_raw, p_raw, sys_ts):
        """每秒接收同步之上下行 throughput 與延遲數據"""
        if ul_raw: self.iperf_ul_cons.append(ul_raw)
        if dl_raw: self.iperf_dl_cons.append(dl_raw)
        if p_raw: self.ping_cons.append(p_raw)

        # 紀錄結構: [秒數, 上行Mbps, 下行Mbps, 延遲ms, 系統時間戳]
        self.test_data.append([round(elapsed, 2), thru_ul, thru_dl, lat, sys_ts])

        # ==================== [新增] 即時寫入與 1MB 切割邏輯 ====================
        try:
            # 判斷當前檔案大小是否已達 1MB (1,048,576 Bytes)
            if os.path.exists(self.current_csv_path) and os.path.getsize(self.current_csv_path) >= 1024 * 1024:
                self.log_file_index += 1
                self.current_csv_path = os.path.join(
                    self.session_dir, f"Handover_Data_{self.log_file_index:03d}.csv"
                )
                with open(self.current_csv_path, 'w', encoding='utf-8-sig') as f:
                    f.write(','.join(self.csv_headers) + '\n')
                self.all_session_csv_files.append(self.current_csv_path)
                logger.info(f"Log 超過 1MB，已自動分割至新檔案: {self.current_csv_path}")

            # 即時追加該秒數據 (以逗號分隔寫入)
            line_str = f"{round(elapsed, 2)},{thru_ul},{thru_dl},{lat},{sys_ts}\n"
            with open(self.current_csv_path, 'a', encoding='utf-8-sig') as f:
                f.write(line_str)
        except Exception as e:
            logger.error(f"即時寫入數據失敗: {e}")
        # =====================================================================

        if elapsed > 0:
            try:
                numeric_arr = np.array([row[:4] for row in self.test_data], dtype=float)
                ul_avg = np.mean(numeric_arr[:, 1]) if self.chk_iperf.isChecked() else 0.0
                dl_avg = np.mean(numeric_arr[:, 2]) if self.chk_iperf.isChecked() else 0.0
                valid_lat = numeric_arr[numeric_arr[:, 3] > 0, 3]
                l_avg = np.mean(valid_lat) if len(valid_lat) > 0 else 0.0

                self.lbl_stats.setText(
                    f"即時摘要 - 上行平均: {ul_avg:.1f} Mbps | 下行平均: {dl_avg:.1f} Mbps | 平均延遲: {l_avg:.1f} ms"
                )

                # 更新繪圖 (顯示最後 100 筆即時滑動視窗)
                window = numeric_arr[-100:]
                self.c1_ul.setData(window[:, 0], window[:, 1])
                self.c1_dl.setData(window[:, 0], window[:, 2])
                self.s2.setData(x=window[:, 0], y=window[:, 3])

                # 完整歷程更新
                self.c3_ul.setData(numeric_arr[:, 0], numeric_arr[:, 1])
                self.c3_dl.setData(numeric_arr[:, 0], numeric_arr[:, 2])
                self.c3p.setData(numeric_arr[:, 0], numeric_arr[:, 3])
                self.p3v2.setGeometry(self.p3.getViewBox().sceneBoundingRect())
            except Exception as e:
                logger.error(f"即時數據更新錯誤: {e}")

    def stop_test(self):
        if self.worker:
            self.worker.stop()
            self.end_time_dt = datetime.now()
            self.start_time_dt = getattr(self, 'start_datetime', self.end_time_dt)
            self.total_duration_sec = (self.end_time_dt - self.start_time_dt).total_seconds()
            
            # 將所有已產生的 1MB 分卷 CSV 加入歸檔清單
            self.generated_files = list(getattr(self, 'all_session_csv_files', []))

            # 將記憶體資料轉換為 DataFrame，供 handle_final_stats 計算統計摘要
            if self.test_data:
                df = pd.DataFrame(self.test_data, columns=self.csv_headers)
                self.current_df = df

    def handle_final_stats(self, sent, success, pcap_path, session_id):
        report_start_time_str = None
        if hasattr(self, 'current_df') and not self.current_df.empty:
            report_start_time_str = self.current_df['System_Timestamp'].iloc[0]

        # ICMP 分析
        if hasattr(self, 'current_df') and not self.current_df.empty and self.chk_ping.isChecked():
            aligned_sent = len(self.current_df)
            aligned_success = len(self.current_df[self.current_df['Latency_ms'].astype(float) > 0])
            sw_loss_rate = ((aligned_sent - aligned_success) / aligned_sent * 100) if aligned_sent > 0 else 0.0
            icmp_sw_report = f"發送: {aligned_sent}, 成功: {aligned_success}, 掉包率: {sw_loss_rate:.2f}%"
        else:
            sw_loss_rate = ((sent - success) / sent * 100) if sent > 0 else 0
            icmp_sw_report = f"發送: {sent}, 成功: {success}, 掉包率: {sw_loss_rate:.2f}%"

        report = f"\n--- [測試結束統計報告] ---\n{icmp_sw_report}\n"

        if pcap_path and os.path.exists(pcap_path):
            self.ping_cons.append(f"> 解析 Session 0x{session_id:04x} 封包...")
            QApplication.processEvents()
            req, rep = run_tshark_analysis(pcap_path, session_id, start_time_str=report_start_time_str)
            p_loss = req - rep
            p_rate = (p_loss / req * 100) if req > 0 else 0.00
            icmp_p_report = f"捕捉 Request: {req}, Reply: {rep}, 掉包率: {p_rate:.2f}%"
            report += f"{icmp_p_report}\n"
            # [修正] 找出所有相關的 pcapng 分卷檔案並加入清單
            import glob
            pcap_prefix = os.path.splitext(pcap_path)[0].split('_000')[0]  # 取得基本前綴
            for p in glob.glob(f"{pcap_prefix}*.pcapng"):
                if hasattr(self, 'generated_files') and p not in self.generated_files:
                    self.generated_files.append(p)
        else:
            icmp_p_report = "無抓包資料"
            report += f"{icmp_p_report}\n"

        self.ping_cons.append(report)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        # 彙總報表生成
        if hasattr(self, 'current_df') and self.current_df is not None:
            df = self.current_df
            try:
                ping_data = df['Latency_ms'].astype(float)
                valid_ping = ping_data[ping_data > 0]
                max_lat = valid_ping.max() if not valid_ping.empty else 0.0
                min_lat = valid_ping.min() if not valid_ping.empty else 0.0
                avg_lat = valid_ping.mean() if not valid_ping.empty else 0.0

                if self.chk_iperf.isChecked():
                    ul_s = df[df['UL_Throughput_Mbps'] != "N/A"]['UL_Throughput_Mbps'].astype(float)
                    dl_s = df[df['DL_Throughput_Mbps'] != "N/A"]['DL_Throughput_Mbps'].astype(float)
                    ul_max = ul_s.max() if not ul_s.empty else 0.0
                    ul_min = ul_s.min() if not ul_s.empty else 0.0
                    ul_avg = ul_s.mean() if not ul_s.empty else 0.0
                    dl_max = dl_s.max() if not dl_s.empty else 0.0
                    dl_min = dl_s.min() if not dl_s.empty else 0.0
                    dl_avg = dl_s.mean() if not dl_s.empty else 0.0
                else:
                    ul_max = ul_min = ul_avg = dl_max = dl_min = dl_avg = "N/A"

                start_time_dt = getattr(self, 'start_time_dt', datetime.now())
                end_time_dt = getattr(self, 'end_time_dt', datetime.now())
                total_duration_sec = getattr(self, 'total_duration_sec', 0.0)
                file_id = getattr(self, 'file_id', int(time.time()))
                summary_path = f"Handover_Summary_{file_id}.xlsx"

                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("10.255.255.255", 1))
                    src_ip = s.getsockname()[0]
                    s.close()
                except:
                    src_ip = "Unknown"

                proto = "UDP" if self.proto_tabs.currentIndex() == 1 else "TCP"
                bind_ip_str = getattr(self, 'current_test_bind_ip', 'Auto (Default)')
                
                ul_bw_display = self.iperf_ul_bw.text().strip() or "Unlimited"
                dl_bw_display = self.iperf_dl_bw.text().strip() or "Unlimited"
                
                summary_data = {
                    "項目": [
                        "測試開始時間", "測試結束時間", "總耗時 (秒)",
                        "本機 IP (Source IP)", "目標 IP (Ping Target)", "伺服器 IP (iperf Server)",
                        "ICMP 測試參數", "Interval", "SessionID",
                        "Ping 指定介面:",
                        "ICMP 軟體統計", "ICMP 封包統計",
                        "iperf 測試參數", "上行埠 (UL Port):", "上行頻寬 (UL BW):", "下行埠 (DL Port):", "下行頻寬 (DL BW):",
                        "TargetTime:", "Protocol:", "Parallel:", "Window:",
                        "iperf 指定介面 (-B):",
                        "iperf 工具版本",
                        "Ping 最大延遲 (ms)", "Ping 最小延遲 (ms)", "Ping 平均延遲 (ms)",
                        "上行最大頻寬 (Uplink Max Mbps)", "上行最小頻寬 (Uplink Min Mbps)", "上行平均頻寬 (Uplink Avg Mbps)",
                        "下行最大頻寬 (Downlink Max Mbps)", "下行最小頻寬 (Downlink Min Mbps)", "下行平均頻寬 (Downlink Avg Mbps)"
                    ],
                    "數值": [
                        start_time_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        end_time_dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        round(total_duration_sec, 2),
                        src_ip,
                        self.ping_target.text(),
                        self.iperf_server.text(),
                        "", f"{self.ping_targetterval.text()}s", session_id,
                        getattr(self, 'current_test_ping_bind_ip', 'Auto (Default)'),
                        icmp_sw_report, icmp_p_report,
                        "", self.iperf_ul_port.text(), ul_bw_display, self.iperf_dl_port.text(), dl_bw_display,
                        f"{self.iperf_time.text()}s", proto,
                        self.tcp_parallel.text() if proto == "TCP" else "N/A", self.tcp_window.text() if proto == "TCP" else "N/A",
                        bind_ip_str,
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
                logger.error(f"產生 Summary 失敗: {e}")

        # 歸檔至 log/<當次測試時間>/
        try:
            log_base_dir = LOG_DIR
            session_folder_name = getattr(self, 'current_session_folder', datetime.now().strftime("%Y%m%d_%H%M%S"))
            target_session_dir = os.path.join(log_base_dir, session_folder_name)
            os.makedirs(target_session_dir, exist_ok=True)

            # [新增防護] 自動補抓當前工作目錄下所有符合該測試時間的 Capture 檔案
            import glob
            for stray_pcap in glob.glob(f"Capture_{session_folder_name}*.pcapng"):
                if stray_pcap not in self.generated_files:
                    self.generated_files.append(stray_pcap)

            # 給予 Windows 系統 0.5 秒釋放檔案 handle
            time.sleep(0.5)

            moved_files = []
            for file_path in getattr(self, 'generated_files', []):
                if os.path.exists(file_path):
                    file_name = os.path.basename(file_path)
                    dest_path = os.path.join(target_session_dir, file_name)
                    if os.path.abspath(file_path) != os.path.abspath(dest_path):
                        if os.path.exists(dest_path):
                            os.remove(dest_path)
                        shutil.move(file_path, dest_path)
                    moved_files.append(dest_path)
                    logger.info(f"檔案已歸檔: {dest_path}")
                else:
                    moved_files.append(file_path)

            self.generated_files = moved_files
            self.ping_cons.append(f"> [儲存] 測試資料已歸檔至: log/{session_folder_name}/")
        except Exception as e:
            logger.error(f"歸檔失敗: {e}")
            self.ping_cons.append(f"> [警告] 歸檔失敗: {e}")

        # 自動上傳
        if hasattr(self, 'generated_files') and self.chk_auto_upload.isChecked():
            self.ping_cons.append("> [自動上傳] 打包並上傳測試日誌...")
            import threading
            from backend_functions import silent_pack_and_upload
            threading.Thread(target=lambda: silent_pack_and_upload(self.generated_files, note="Auto_HO_Automation"), daemon=True).start()

    def manual_upload(self):
        files, _ = QFileDialog.getOpenFileNames(
            self, "選取要打包的檔案", "", "All Files (*);;Excel Files (*.xlsx);;XML Files (*.xml);;Log Files (*.log *.pcapng)"
        )
        if not files:
            return
        note, ok = QInputDialog.getText(self, "輸入備註", "請輸入測試標註 (可留空):", text="Manual_Upload")
        if not ok:
            return

        self.ping_cons.append(f"> [手動上傳] 正在打包 {len(files)} 個檔案...")
        import threading
        from backend_functions import silent_pack_and_upload
        def bg_manual_upload_worker(files_list, upload_note):
            success, result_msg = silent_pack_and_upload(files_list, note=upload_note)
            if success:
                logger.info(f"上傳成功: {result_msg}")
                self.ping_cons.append(f"上傳成功: {result_msg}\n")
            else:
                logger.error(f"上傳失敗: {result_msg}")
                self.ping_cons.append(f"上傳失敗: {result_msg}\n")
        threading.Thread(target=bg_manual_upload_worker, args=(files, note), daemon=True).start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = HandoverTester()
    win.show()
    sys.exit(app.exec())
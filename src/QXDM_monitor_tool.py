import win32com.client
import time

def qxdm_handover_test():
    # 1. 啟動 QXDM Application
    qxdm_app = win32com.client.DispatchEx("QXDM.Application")
    
    # 2. 取得 Automation 介面
    qxdm_auto = qxdm_app.GetAutomation()
    
    # 3. 連接設備 (COM Port 需根據實際狀況修改)
    # 假設 Port 為 10
    qxdm_auto.Connect(10)
    
    if qxdm_auto.IsConnected():
        print("Connected to UE successfully.")
    else:
        print("Connection failed.")
        return

    # 4. 加載過濾文件 (.dmc) 以獲取 NR RRC 訊息
    # 建議包含 0xB821 (NR5G RRC OTA Packet)
    qxdm_auto.LoadConfig(r"C:\Path\To\Your\NR_Handover.dmc")

    print("Starting Log Capture...")
    
    # 模擬測試運行時間
    try:
        for _ in range(30):  # 監控 30 秒
            # 獲取目前的 Item 數量
            item_count = qxdm_auto.GetItemCount()
            
            if item_count > 0:
                # 取得最後一個 Item (索引從 0 開始)
                latest_item = qxdm_auto.GetItem(item_count - 1)
                
                # 判斷是否為 NR RRC OTA Packet (範例 ID: 0xB821)
                if latest_item.GetItemKeyText() == "0xB821":
                    summary = latest_item.GetItemSummary()
                    print(f"Detected NR RRC Msg: {summary}")
                    
                    # 判斷邏輯：尋找 'rrcReconfiguration' 且包含 'reconfigurationWithSync'
                    if "reconfigurationWithSync" in summary:
                        print(">>> Handover Command (Sync) Detected!")
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        pass

    # 5. 儲存結果並中斷連線
    qxdm_auto.SaveItemStore(r"C:\Logs\Handover_Test.isf")
    print("Test finished and log saved.")

if __name__ == "__main__":
    qxdm_handover_test()
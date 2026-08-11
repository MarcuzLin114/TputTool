import os
import sys
import time
import subprocess
import psutil
import pyautogui
import win32gui

# ==================== 配置區 ====================
QXDM_EXE_PATH = r"C:\Program Files\Qualcomm\QXDM5\QXDM.exe"

# 影像辨識小圖路徑 (確保這兩張圖與 test.py 放在同一個目錄下)
IMAGE_DIR = os.path.dirname(os.path.abspath(__file__))
CONNECT_BTN_IMG = os.path.join(IMAGE_DIR, "connect_btn.png")
YES_BTN_IMG = os.path.join(IMAGE_DIR, "yes_btn.png")

# 安全保護：滑鼠快速移到螢幕「左上角」可強制中斷腳本，防止自動化失控
pyautogui.FAILSAFE = True
# 降低 PyAutoGUI 每次操作的微小延遲，提高流暢度
pyautogui.PAUSE = 0.3
# ================================================

def is_in_background_processes():
    """檢測 QXDM 是否存在於背景處理程序中"""
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and 'qxdm' in proc.info['name'].lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return False

def find_qxdm_window_handle():
    """精準匹配 QXDM 軟體的主視窗，排除瀏覽器干擾"""
    qxdm_hwnds = []
    def enum_windows_callback(hwnd, extra):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            title_lower = title.lower()
            if 'qxdm' in title_lower and 'chrome' not in title_lower and 'edge' not in title_lower:
                if 'qxdm_pro' in title_lower or 'disconnected' in title_lower or 'connected' in title_lower:
                    qxdm_hwnds.append((hwnd, title))
        return True
    win32gui.EnumWindows(enum_windows_callback, None)
    return qxdm_hwnds

def handle_device_connection(qxdm_hwnd):
    """【步驟 2】自動搜尋 Device Selection 視窗，點擊並傳遞控制權"""
    print("\n⌨️【步驟 1】發送 'F6' 快捷鍵呼叫 Device Selection 視窗...")
    win32gui.SetForegroundWindow(qxdm_hwnd)
    time.sleep(1)
    
    pyautogui.press('f6')
    print("⏳ 等待 Device Selection 視窗展開...")
    time.sleep(3) 

    # 自動搜尋 Device Selection 主視窗
    dev_sel_hwnd = 0
    def find_device_selection_window(hwnd, extra):
        nonlocal dev_sel_hwnd
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if "device selection" in title.lower():
                dev_sel_hwnd = hwnd
        return True
    win32gui.EnumWindows(find_device_selection_window, None)

    if dev_sel_hwnd != 0:
        print(f"🎯 [自動搜尋] 成功鎖定子視窗 'Device Selection' (HWND: {dev_sel_hwnd})！")
        win32gui.ShowWindow(dev_sel_hwnd, 9) 
        win32gui.SetForegroundWindow(dev_sel_hwnd)
        time.sleep(1)
    else:
        print("❌ 錯誤：在前端畫面上找不到 'Device Selection' 視窗。")
        return False

    print("📸【步驟 2】開始自動搜尋與選擇目標 (Connect 按鈕)...")
    
    # 動態邊界計算
    rect = win32gui.GetWindowRect(dev_sel_hwnd)
    win_left, win_top, win_right, win_bottom = rect
    win_width = win_right - win_left
    win_height = win_bottom - win_top
    
    dynamic_connect_x = win_left + (win_width - 45)
    dynamic_connect_y = win_top + 65
    
    # 點擊欄位確保聚焦
    pyautogui.click(win_left + 150, win_top + 130)
    time.sleep(0.5)
    
    print(f"   -> [動態點擊] 發送點擊至相對座標 Connect 按鈕: ({dynamic_connect_x}, {dynamic_connect_y})")
    pyautogui.click(dynamic_connect_x, dynamic_connect_y)
    
    print("⏳ [時序控制] 已點擊 Connect，強迫等待 1.5 秒讓 Golden DMC 視窗彈出...")
    time.sleep(1.5)

    # 【核心修正】將父視窗的 HWND 傳進去，以便搜尋其子對話框
    return handle_golden_dmc_popup(dev_sel_hwnd, qxdm_hwnd)

def check_connection_success(qxdm_hwnd):
    """檢查主視窗標題狀態"""
    current_title = win32gui.GetWindowText(qxdm_hwnd)
    if "Disconnected" in current_title:
        print("⚠️ 檢測到主視窗仍顯示 'Disconnected'，連線未成功，關閉對話框。")
        pyautogui.press('esc')
        return False
    return True

def handle_golden_dmc_popup(parent_hwnd, qxdm_hwnd):
    """
    【步驟 3 子視窗級別修正】
    同時搜尋全域與父視窗的子層級 (Child Windows)，確保抓到 Golden DMC Check
    """
    print("🖥️【步驟 3】進入彈窗監聽階段，深入子層級等待 'Golden DMC Check'...")
    
    dmc_hwnd = 0
    timeout = 8  # 最長等待 8 秒
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        # 策略 A：在父視窗（Device Selection）的子控制項中列舉
        def find_child_dmc(hwnd, extra):
            nonlocal dmc_hwnd
            if win32gui.IsWindowVisible(hwnd):
                title = win32gui.GetWindowText(hwnd)
                if "golden dmc" in title.lower():
                    dmc_hwnd = hwnd
            return True
            
        try:
            win32gui.EnumChildWindows(parent_hwnd, find_child_dmc, None)
        except Exception:
            pass
            
        # 策略 B：如果 A 沒撈到，試試看是不是掛在 QXDM 主視窗下面
        if dmc_hwnd == 0:
            try:
                win32gui.EnumChildWindows(qxdm_hwnd, find_child_dmc, None)
            except Exception:
                pass
                
        # 策略 C：全域模糊獨立窗搜尋（原本的邏輯留作備份）
        if dmc_hwnd == 0:
            win32gui.EnumWindows(find_child_dmc, None)

        # 只要有一條路徑撈到 HWND，立刻破繭而出
        if dmc_hwnd != 0:
            print(f"🎯 [子視窗精準捕捉] 成功抓到彈窗！(HWND: {dmc_hwnd})")
            break
            
        time.sleep(0.2)

    # 萬一真的還是因為高通底層控制項奇特而拿不到 HWND，啟動盲打
    if dmc_hwnd == 0:
        print("⚠️ 警告：子層級仍未回傳 HWND，高通可能隱藏了標題列。啟動智慧盲打方案...")
        # 因為彈窗通常會強行奪取全系統焦點 (Modal Dialog)
        # 我們直接發送鍵盤組合，並且點擊 Device Selection 視窗的中心偏下方（彈窗疊在它正中間）
        pyautogui.press('y')
        time.sleep(0.3)
        pyautogui.press('enter')
        
        # 備用點擊：直接取 Device Selection 視窗的中心點
        p_rect = win32gui.GetWindowRect(parent_hwnd)
        p_left, p_top, p_right, p_bottom = p_rect
        center_x = p_left + ((p_right - p_left) // 2)
        center_y = p_top + ((p_bottom - p_top) // 2) + 65 # 往下偏移到按鈕區
        
        print(f"   -> [智慧盲打] 點擊父視窗相對中心點: ({center_x}, {center_y})")
        pyautogui.click(center_x, center_y)
        print("🎉【連線完成】已透過智慧防禦機制發送連線確認。")
        return True

    # 3. 順利拿到 HWND，執行標準精準點擊
    try:
        win32gui.ShowWindow(dmc_hwnd, 9)
        win32gui.SetForegroundWindow(dmc_hwnd)
        time.sleep(0.3)

        rect = win32gui.GetWindowRect(dmc_hwnd)
        win_left, win_top, win_right, win_bottom = rect
        
        win_left += 7
        win_right -= 7
        win_bottom -= 7
        win_width = win_right - win_left
        win_height = win_bottom - win_top

        yes_x = win_left + int(win_width * 0.43)
        yes_y = win_top + int(win_height * 0.72)

        print(f"   -> [滑鼠制導] 實體子視窗 'Yes' 座標: ({yes_x}, {yes_y})")
        pyautogui.click(yes_x, yes_y)
        print("🎉【連線成功】已精準擊中 Yes 按鈕！")
        return True

    except Exception as e:
        print(f"❌ 實體點擊失敗: {e}")
        return False

def launch_qxdm_flow():
    print("=== QXDM 自動化視窗控制流程 ===")
    
    if not os.path.exists(QXDM_EXE_PATH):
        print(f"❌ 錯誤：找不到 QXDM 執行檔: {QXDM_EXE_PATH}")
        sys.exit(1)
        
    print("💻【步驟 1】透過 Windows Terminal 喚醒 QXDM5...")
    cmd = f'wt.exe "{QXDM_EXE_PATH}"'
    subprocess.Popen(cmd, shell=True)
    
    print("📊【步驟 2】等待 QXDM 5 出現在 [背景處理程序]...")
    bg_timeout = 15
    start_time = time.time()
    found_bg = False
    while time.time() - start_time < bg_timeout:
        if is_in_background_processes():
            print("   -> [OK] 已在背景處理程序中檢測到 QXDM！")
            found_bg = True
            break
        time.sleep(0.5)
        
    if not found_bg:
        print("❌ 錯誤：超時未在背景處理程序中偵測到 QXDM。")
        sys.exit(1)
        
    print("🖥️【步驟 3】等待 QXDM 5 載入完成並出現在 [應用程式] 清單中...")
    app_timeout = 25
    app_start_time = time.time()
    target_hwnd = None
    
    while time.time() - app_start_time < app_timeout:
        windows = find_qxdm_window_handle()
        if windows:
            target_hwnd = windows[0][0]
            actual_title = windows[0][1]
            print(f"   -> [OK] 檢測成功！找到 QXDM 視窗: '{actual_title}'")
            break
        time.sleep(1)
        
    if not target_hwnd:
        print("❌ 錯誤：超時未在應用程式中偵測到 QXDM 5 展開。")
        sys.exit(1)

    print("🔲【步驟 4】正在將 QXDM 5 視窗最大化...")
    win32gui.ShowWindow(target_hwnd, 9) # 恢復並激活
    win32gui.SetForegroundWindow(target_hwnd)
    time.sleep(1)
    pyautogui.hotkey('win', 'up')
    print("🎉 QXDM 5 視窗已成功最大化展開！")
    time.sleep(1)

    # 進入連線序列控制
    handle_device_connection(target_hwnd)

if __name__ == "__main__":
    launch_qxdm_flow()
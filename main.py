import customtkinter as ctk
from tkinter import filedialog
import threading
import os
import time

from src.engines import ScanEngineManager
from src.report_generator import ReportGenerator

# --- Tema Ayarları (Modern, Sade, Kurumsal) ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG_MAIN = "#0d1117"
BG_SURFACE = "#161b22"
BG_CARD = "#21262d"
TEXT_PRIMARY = "#c9d1d9"
TEXT_SECONDARY = "#8b949e"
ACCENT_GREEN = "#2ea043"
ACCENT_BLUE = "#58a6ff"
ACCENT_RED = "#f85149"
ACCENT_YELLOW = "#d29922"

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Sıfır Güven (Zero Trust) Tüneli V2")
        self.geometry("1100x700")
        self.configure(fg_color=BG_MAIN)
        import sys
        if getattr(sys, 'frozen', False):
            self.project_root = os.path.dirname(sys.executable)
        else:
            self.project_root = os.path.dirname(os.path.abspath(__file__))
        self.target_path = None
        
        self._build_ui()
        self.log_terminal("[Sistem Başlatıldı] Sıfır Güven (Zero Trust) Tüneli v2.0", level="info")
        self.log_terminal("[Motorlar] Semgrep, Detect-Secrets, OSV-Scanner yüklendi.", level="info")
        self.log_terminal("[Durum] Hedef seçilmesi bekleniyor...", level="info")

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        
        # --- ÜST PANEL (HEDEF SEÇİMİ) ---
        self.top_frame = ctk.CTkFrame(self, fg_color=BG_SURFACE, corner_radius=10)
        self.top_frame.grid(row=0, column=0, padx=20, pady=20, sticky="ew")
        self.top_frame.grid_columnconfigure(1, weight=1)
        
        self.btn_select_file = ctk.CTkButton(
            self.top_frame, text="Tek Dosya Seç", fg_color=BG_CARD, hover_color="#30363d",
            font=("Segoe UI", 13, "bold"), command=self.select_file
        )
        self.btn_select_file.grid(row=0, column=0, padx=15, pady=20)
        
        self.btn_select_folder = ctk.CTkButton(
            self.top_frame, text="Klasör (Proje) Seç", fg_color=BG_CARD, hover_color="#30363d",
            font=("Segoe UI", 13, "bold"), command=self.select_folder
        )
        self.btn_select_folder.grid(row=0, column=1, padx=15, pady=20, sticky="w")
        
        self.lbl_target = ctk.CTkLabel(
            self.top_frame, text="Hedef: Seçilmedi", text_color=TEXT_SECONDARY, font=("Segoe UI", 14)
        )
        self.lbl_target.grid(row=0, column=2, padx=15, pady=20, sticky="e")
        
        self.btn_scan = ctk.CTkButton(
            self.top_frame, text="TÜNELİ BAŞLAT", fg_color=ACCENT_GREEN, hover_color="#238636", text_color="white",
            font=("Segoe UI", 14, "bold"), command=self.start_scan, state="disabled"
        )
        self.btn_scan.grid(row=0, column=3, padx=15, pady=20)

        # --- ORTA PANEL (İSTATİSTİK & TERMİNAL) ---
        self.mid_frame = ctk.CTkFrame(self, fg_color=BG_MAIN)
        self.mid_frame.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.mid_frame.grid_columnconfigure(0, weight=1)
        self.mid_frame.grid_rowconfigure(1, weight=1)
        
        self.progress = ctk.CTkProgressBar(self.mid_frame, mode="indeterminate", progress_color=ACCENT_BLUE, fg_color=BG_CARD, height=6)
        self.progress.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        self.progress.set(0)
        
        self.terminal = ctk.CTkTextbox(
            self.mid_frame, font=("Consolas", 14), fg_color="#010409", text_color=TEXT_PRIMARY, corner_radius=10
        )
        self.terminal.grid(row=1, column=0, sticky="nsew")
        
        # Terminal Tag Konfigürasyonları
        self.terminal.tag_config("info", foreground=ACCENT_BLUE)
        self.terminal.tag_config("success", foreground=ACCENT_GREEN)
        self.terminal.tag_config("error", foreground=ACCENT_RED)
        self.terminal.tag_config("warning", foreground=ACCENT_YELLOW)

    def log_terminal(self, message, level="info"):
        timestamp = time.strftime("[%H:%M:%S]")
        self.terminal.insert("end", f"{timestamp} {message}\n", level)
        self.terminal.see("end")

    def select_file(self):
        filepath = filedialog.askopenfilename(title="Taranacak Dosyayı Seçin")
        if filepath:
            self.target_path = filepath
            self.lbl_target.configure(text=f"Hedef: {os.path.basename(filepath)}", text_color=TEXT_PRIMARY)
            self.btn_scan.configure(state="normal")
            self.log_terminal(f"Dosya seçildi: {filepath}", "info")

    def select_folder(self):
        folderpath = filedialog.askdirectory(title="Taranacak Klasörü Seçin")
        if folderpath:
            self.target_path = folderpath
            self.lbl_target.configure(text=f"Hedef: {os.path.basename(folderpath)}/ (Klasör)", text_color=TEXT_PRIMARY)
            self.btn_scan.configure(state="normal")
            self.log_terminal(f"Klasör seçildi: {folderpath}", "info")

    def start_scan(self):
        if not self.target_path:
            return
            
        self.btn_scan.configure(state="disabled", text="TARANIYOR...")
        self.btn_select_file.configure(state="disabled")
        self.btn_select_folder.configure(state="disabled")
        self.progress.start()
        
        self.terminal.delete("1.0", "end")
        self.log_terminal("==========================================", "warning")
        self.log_terminal("TÜNEL AKTİF: Derin Analiz Başlıyor...", "success")
        self.log_terminal(f"Hedef: {self.target_path}", "info")
        self.log_terminal("==========================================", "warning")
        
        # Taramayı arka planda başlat
        threading.Thread(target=self._run_engines_thread, daemon=True).start()

    def _run_engines_thread(self):
        engine_mgr = ScanEngineManager(self.project_root)
        
        # 1. Semgrep (Mantık & Enjeksiyon)
        self.log_terminal("\n[1/3] Katman 1 & 2: Semgrep (Mantık & Kod Kalitesi) Başlatıldı...", "info")
        semgrep_res = engine_mgr.run_semgrep(self.target_path)
        if semgrep_res["success"]:
            self.log_terminal("   -> Semgrep Analizi Tamamlandı.", "success")
        else:
            self.log_terminal(f"   -> Semgrep Hatası: {semgrep_res.get('error')}", "error")
            
        # 2. Detect-Secrets (Sızıntı)
        self.log_terminal("\n[2/3] Katman 3: Detect-Secrets (Yüksek Entropi Şifre Avı) Başlatıldı...", "info")
        secrets_res = engine_mgr.run_detect_secrets(self.target_path)
        if secrets_res["success"]:
            self.log_terminal("   -> Detect-Secrets Analizi Tamamlandı.", "success")
        else:
            self.log_terminal(f"   -> Detect-Secrets Hatası: {secrets_res.get('error')}", "error")
            
        # 3. OSV-Scanner (Zafiyetli Kütüphaneler)
        self.log_terminal("\n[3/3] Katman 4: OSV-Scanner (Tedarik Zinciri ve Kütüphane) Başlatıldı...", "info")
        osv_res = engine_mgr.run_osv_scanner(self.target_path)
        if osv_res["success"]:
            self.log_terminal("   -> OSV-Scanner Analizi Tamamlandı.", "success")
        else:
            self.log_terminal(f"   -> OSV-Scanner Hatası: {osv_res.get('error')} (İnternet bağlantınızı kontrol edin veya desteklenmeyen dosya tipi)", "warning")
            
        self.log_terminal("\n[+] Bütün Motorlar Tamamlandı. Rapor Oluşturuluyor...", "info")
        
        # Raporlama
        reporter = ReportGenerator(os.path.join(self.project_root, "dist") if os.path.exists(os.path.join(self.project_root, "dist")) else self.project_root)
        report_path = reporter.generate_report(
            self.target_path, 
            semgrep_res.get("stdout", "{}"), 
            secrets_res.get("stdout", "{}"), 
            osv_res.get("stdout", "{}")
        )
        
        # Arayüzü Güncelle
        self.after(0, self._finish_scan, report_path)
        
    def _finish_scan(self, report_path):
        self.progress.stop()
        self.progress.set(1)
        self.btn_scan.configure(state="normal", text="YENİDEN TARA")
        self.btn_select_file.configure(state="normal")
        self.btn_select_folder.configure(state="normal")
        
        self.log_terminal("\n==========================================", "warning")
        self.log_terminal(f"GÖREV TAMAMLANDI! HTML Raporu Tarayıcıda Açıldı.", "success")
        self.log_terminal(f"Rapor Kayıt Yeri: {report_path}", "info")
        self.log_terminal("==========================================", "warning")

if __name__ == "__main__":
    app = App()
    app.mainloop()

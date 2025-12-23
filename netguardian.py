import customtkinter as ctk
import scapy.all as scapy
import socket
import threading
import requests
import time
from datetime import datetime
from tkinter import filedialog

# --- STYLE ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NetworkEngine:
    COMMON_PORTS = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3389: "RDP"}

    def __init__(self):
        self.packet_count = 0
        self.known_macs = set()

    def get_my_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            return s.getsockname()[0]
        except:
            return '127.0.0.1'
        finally:
            s.close()

    def get_vendor(self, mac):
        try:
            # Używamy stabilnego API do sprawdzania producenta
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=0.7)
            return response.text if response.status_code == 200 else "Unknown"
        except:
            return "---"

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown-Host"

    def get_os_and_ping(self, ip):
        """Zgaduje OS na podstawie TTL i mierzy czas odpowiedzi"""
        try:
            start = time.time()
            ans = scapy.sr1(scapy.IP(dst=ip) / scapy.ICMP(), timeout=1, verbose=False)
            end = time.time()
            if ans:
                ping = int((end - start) * 1000)
                ttl = ans.ttl
                os_type = "Linux/Android" if ttl <= 64 else "Windows"
                return f"{ping}ms ({os_type})"
            return "---"
        except:
            return "---"


class NetGuardianGhost(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- PARAMETRY OKNA ---
        self.width = 1000  # Poszerzone dla dodatkowych danych
        self.height = 650
        self.title("NetGuardian v2.1 - Ghost Edition")
        self.geometry(f"{self.width}x{self.height}")
        self.resizable(False, False)
        self.attributes("-alpha", 0.9)

        self.engine = NetworkEngine()
        self.setup_ui()

        threading.Thread(target=self.activity_monitor, daemon=True).start()

    def setup_ui(self):
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=25, pady=15)

        # NAGŁÓWEK
        self.header = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.header.pack(fill="x", pady=(0, 10))

        self.title_label = ctk.CTkLabel(self.header, text="👻 NETGUARDIAN GHOST PRO",
                                        font=ctk.CTkFont(size=24, weight="bold", family="Consolas"))
        self.title_label.pack(side="left")

        self.activity_val = ctk.CTkLabel(self.header, text="RUCH: 0 pkt/s",
                                         text_color="#00FFCC", font=("Consolas", 13))
        self.activity_val.pack(side="right")

        # PANEL KONTROLNY
        self.ctrl_panel = ctk.CTkFrame(self.main_container, border_width=1, border_color="#333")
        self.ctrl_panel.pack(fill="x", pady=10)

        self.ip_input = ctk.CTkEntry(self.ctrl_panel, placeholder_text="Zakres IP", width=250, height=35)
        self.ip_input.insert(0, ".".join(self.engine.get_my_ip().split('.')[:-1]) + ".0/24")
        self.ip_input.pack(side="left", padx=20, pady=15)

        self.btn_scan = ctk.CTkButton(self.ctrl_panel, text="DEEP SCAN", command=self.run_scan_thread,
                                      width=140, height=35, font=ctk.CTkFont(weight="bold"))
        self.btn_scan.pack(side="left", padx=5)

        self.btn_export = ctk.CTkButton(self.ctrl_panel, text="EXPORT", command=self.export_to_txt,
                                        fg_color="#28a745", width=100, height=35)
        self.btn_export.pack(side="left", padx=5)

        # OBSZAR WYNIKÓW
        self.results = ctk.CTkTextbox(self.main_container, font=("Consolas", 12), border_width=1, border_color="#222")
        self.results.pack(fill="both", expand=True, pady=10)
        self.clear_results()

        # STOPKA
        self.footer = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.footer.pack(fill="x", pady=(5, 0))

        self.author = ctk.CTkLabel(self.footer, text="Autor: Stanisław Kozioł",
                                   font=("Consolas", 12, "italic"), text_color="#666")
        self.author.pack(side="left")

        self.opacity_slider = ctk.CTkSlider(self.footer, from_=0.3, to=1.0, width=150, command=self.adjust_opacity)
        self.opacity_slider.set(0.9)
        self.opacity_slider.pack(side="right", padx=10)

        self.status = ctk.CTkLabel(self.footer, text="READY", font=("Consolas", 12), text_color="#3b8ed0")
        self.status.pack(side="right", padx=30)

    def clear_results(self):
        self.results.delete("0.0", "end")
        # Nagłówek tabeli z precyzyjnym wyjustowaniem
        header = f"{'IP ADDRESS':<16} | {'HOSTNAME':<18} | {'MAC ADDRESS':<18} | {'VENDOR':<18} | {'OS / PING'}\n"
        self.results.insert("end", header)
        self.results.insert("end", "-" * 95 + "\n")

    def adjust_opacity(self, value):
        self.attributes("-alpha", value)

    def activity_monitor(self):
        def count_pkt(pkt): self.engine.packet_count += 1

        while True:
            scapy.sniff(prn=count_pkt, timeout=1, store=0)
            self.activity_val.configure(text=f"RUCH: {self.engine.packet_count} pkt/s")
            self.engine.packet_count = 0

    def run_scan_thread(self):
        threading.Thread(target=self.execute_scan, daemon=True).start()

    def execute_scan(self):
        self.btn_scan.configure(state="disabled")
        target = self.ip_input.get()
        self.clear_results()
        self.status.configure(text="DEEP SCANNING...", text_color="orange")

        try:
            # Skan ARP
            arp_req = scapy.ARP(pdst=target)
            pkt = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / arp_req
            ans = scapy.srp(pkt, timeout=2, verbose=False)[0]

            for _, r in ans:
                ip, mac = r.psrc, r.hwsrc

                # Pobieranie rozszerzonych informacji
                vendor = self.engine.get_vendor(mac)
                host = self.engine.get_hostname(ip)
                os_ping = self.engine.get_os_and_ping(ip)

                # Formatowanie linii
                line = f"{ip:<16} | {host[:17]:<18} | {mac:<18} | {vendor[:17]:<18} | {os_ping}\n"
                self.results.insert("end", line)
                self.results.see("end")

            self.status.configure(text=f"SCAN COMPLETE: {len(ans)} DEVICES", text_color="green")
        except Exception as e:
            self.status.configure(text="SCAN ERROR", text_color="red")

        self.btn_scan.configure(state="normal")

    def export_to_txt(self):
        data = self.results.get("0.0", "end")
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="NetGuardian_DeepScan.txt")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(data)
            self.status.configure(text="FILE SAVED")


if __name__ == "__main__":
    app = NetGuardianGhost()
    app.mainloop()
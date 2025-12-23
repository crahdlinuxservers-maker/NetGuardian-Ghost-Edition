# ---------------------------------------------------------
# Project: NetGuardian v2.1 - Ghost Edition
# Author: Stanisław Kozioł (crahdlinuxservers-maker)
# License: Educational / Open Source
# ---------------------------------------------------------

import customtkinter as ctk
import scapy.all as scapy
import socket
import threading
import requests
import time
from datetime import datetime
from tkinter import filedialog

# --- KONFIGURACJA ŚRODOWISKA ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NetworkEngine:
    """Silnik odpowiedzialny za niskopoziomowe operacje sieciowe."""

    def __init__(self):
        self.packet_count = 0
        self.known_macs = set()

    def get_local_ip(self):
        """Pobiera adres IP urządzenia w sieci lokalnej."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            return s.getsockname()[0]
        except Exception:
            return '127.0.0.1'
        finally:
            s.close()

    def get_vendor(self, mac):
        """Identyfikuje producenta na podstawie adresu MAC (API)."""
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=0.8)
            return response.text if response.status_code == 200 else "Unknown Device"
        except Exception:
            return "---"

    def get_hostname(self, ip):
        """Wykonuje wsteczne zapytanie DNS w celu ustalenia nazwy hosta."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown-Host"

    def analyze_os_and_ping(self, ip):
        """Szacuje OS (TTL) oraz mierzy opóźnienie (ICMP)."""
        try:
            start = time.time()
            packet = scapy.IP(dst=ip) / scapy.ICMP()
            response = scapy.sr1(packet, timeout=1, verbose=False)
            end = time.time()

            if response:
                latency = int((end - start) * 1000)
                # TTL Logic: Windows ok. 128, Linux/Android ok. 64
                os_hint = "Win" if response.ttl > 64 else "Linux/And"
                return f"{latency}ms ({os_hint})"
            return "Timeout"
        except Exception:
            return "---"


class NetGuardianApp(ctk.CTk):
    """Główna klasa interfejsu użytkownika Ghost Edition."""

    def __init__(self):
        super().__init__()

        # Konfiguracja okna (Fixed Size)
        self.title("NetGuardian v2.1 - Ghost Edition")
        self.width = 1000
        self.height = 650
        self.geometry(f"{self.width}x{self.height}")
        self.resizable(False, False)
        self.attributes("-alpha", 0.9)  # Domyślna przezroczystość

        self.engine = NetworkEngine()
        self._build_ui()

        # Uruchomienie monitora ruchu w oddzielnym wątku
        threading.Thread(target=self._traffic_monitor_loop, daemon=True).start()

    def _build_ui(self):
        """Inicjalizacja i rozmieszczenie elementów GUI."""
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True, padx=25, pady=15)

        # Sekcja Nagłówka
        self.header = ctk.CTkFrame(self.container, fg_color="transparent")
        self.header.pack(fill="x", pady=(0, 10))

        self.lbl_title = ctk.CTkLabel(self.header, text="👻 NETGUARDIAN GHOST PRO",
                                      font=ctk.CTkFont(size=24, weight="bold", family="Consolas"))
        self.lbl_title.pack(side="left")

        self.lbl_traffic = ctk.CTkLabel(self.header, text="RUCH: 0 pkt/s",
                                        text_color="#00FFCC", font=("Consolas", 13))
        self.lbl_traffic.pack(side="right")

        # Sekcja Sterowania
        self.panel_ctrl = ctk.CTkFrame(self.container, border_width=1, border_color="#333")
        self.panel_ctrl.pack(fill="x", pady=10)

        self.ent_ip = ctk.CTkEntry(self.panel_ctrl, placeholder_text="Zakres IP (np. 192.168.1.0/24)",
                                   width=280, height=35)
        default_range = ".".join(self.engine.get_local_ip().split('.')[:-1]) + ".0/24"
        self.ent_ip.insert(0, default_range)
        self.ent_ip.pack(side="left", padx=20, pady=15)

        self.btn_scan = ctk.CTkButton(self.panel_ctrl, text="DEEP SCAN", command=self._start_scan_thread,
                                      width=140, height=35, font=ctk.CTkFont(weight="bold"))
        self.btn_scan.pack(side="left", padx=5)

        self.btn_save = ctk.CTkButton(self.panel_ctrl, text="EXPORT REPORT", command=self._export_report,
                                      fg_color="#28a745", hover_color="#218838", width=120, height=35)
        self.btn_save.pack(side="left", padx=5)

        # Sekcja Wyników (Wyjustowana Tabela)
        self.txt_results = ctk.CTkTextbox(self.container, font=("Consolas", 12), border_width=1, border_color="#222")
        self.txt_results.pack(fill="both", expand=True, pady=10)
        self._init_table_header()

        # Sekcja Stopki
        self.footer = ctk.CTkFrame(self.container, fg_color="transparent")
        self.footer.pack(fill="x", pady=(5, 0))

        self.lbl_author = ctk.CTkLabel(self.footer, text="Autor: Stanisław Kozioł",
                                       font=("Consolas", 12, "italic"), text_color="#666")
        self.lbl_author.pack(side="left")

        self.sld_opacity = ctk.CTkSlider(self.footer, from_=0.3, to=1.0, width=150, command=self._set_opacity)
        self.sld_opacity.set(0.9)
        self.sld_opacity.pack(side="right", padx=10)

        self.lbl_status = ctk.CTkLabel(self.footer, text="SYSTEM READY", font=("Consolas", 12), text_color="#3b8ed0")
        self.lbl_status.pack(side="right", padx=30)

    def _init_table_header(self):
        """Resetuje widok tabeli i wstawia nagłówki kolumn."""
        self.txt_results.delete("0.0", "end")
        header = f"{'IP ADDRESS':<16} | {'HOSTNAME':<20} | {'MAC ADDRESS':<18} | {'VENDOR':<18} | {'OS / PING'}\n"
        separator = "-" * 98 + "\n"
        self.txt_results.insert("end", header + separator)

    def _set_opacity(self, val):
        self.attributes("-alpha", val)

    def _traffic_monitor_loop(self):
        """Wątek monitorujący aktywność pakietów w czasie rzeczywistym."""

        def callback(pkt): self.engine.packet_count += 1

        while True:
            scapy.sniff(prn=callback, timeout=1, store=0)
            self.lbl_traffic.configure(text=f"RUCH: {self.engine.packet_count} pkt/s")
            self.engine.packet_count = 0

    def _start_scan_thread(self):
        threading.Thread(target=self._execute_deep_scan, daemon=True).start()

    def _execute_deep_scan(self):
        """Główna logika skanowania sieci ARP."""
        self.btn_scan.configure(state="disabled")
        target_range = self.ent_ip.get()
        self._init_table_header()
        self.lbl_status.configure(text="DEEP SCANNING...", text_color="orange")

        try:
            # Tworzenie pakietu ARP Broadcast
            arp_req = scapy.ARP(pdst=target_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            ans = scapy.srp(broadcast / arp_req, timeout=2, verbose=False)[0]

            new_devices_flag = False
            for _, rcv in ans:
                ip, mac = rcv.psrc, rcv.hwsrc

                # Pobieranie danych rozszerzonych
                vendor = self.engine.get_vendor(mac)
                host = self.engine.get_hostname(ip)
                os_ping = self.engine.analyze_os_and_ping(ip)

                # Logika wykrywania nowych urządzeń (Intruder Detection)
                prefix = ""
                if len(self.engine.known_macs) > 0 and mac not in self.engine.known_macs:
                    prefix = "!"
                    new_devices_flag = True

                # Formatowanie linii wynikowej (stałe szerokości kolumn)
                line = f"{prefix}{ip:<15} | {host[:19]:<20} | {mac:<18} | {vendor[:17]:<18} | {os_ping}\n"
                self.txt_results.insert("end", line)
                self.txt_results.see("end")
                self.engine.known_macs.add(mac)

            status_msg = f"FOUND: {len(ans)} DEVICES"
            status_color = "green"
            if new_devices_flag:
                status_msg = "⚠️ DETECTED NEW DEVICE!"
                status_color = "red"

            self.lbl_status.configure(text=status_msg, text_color=status_color)

        except Exception as e:
            self.lbl_status.configure(text="SCAN ERROR", text_color="red")
            self.txt_results.insert("end", f"\n[!] Error: {str(e)}")

        self.btn_scan.configure(state="normal")

    def _export_report(self):
        """Zapisuje zawartość okna wyników do pliku zewnętrznego."""
        content = self.txt_results.get("0.0", "end")
        if len(content) < 150: return  # Brak danych do zapisu

        filename = f"NetGuardian_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.txt"
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=filename)

        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self.lbl_status.configure(text="REPORT EXPORTED", text_color="green")


if __name__ == "__main__":
    # Program wymaga bibliotek: pip install customtkinter scapy requests
    # Wymagany sterownik Npcap: https://npcap.com/
    app = NetGuardianApp()
    app.mainloop()

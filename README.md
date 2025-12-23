# 👻 NetGuardian v2.1 - Ghost Edition

**Zaawansowane narzędzie do audytu, monitoringu i zabezpieczania sieci lokalnych (LAN).**

NetGuardian to profesjonalna aplikacja typu Network Scanner, łącząca niskopoziomową analizę pakietów z nowoczesnym, transparentnym interfejsem użytkownika. Program został zaprojektowany do błyskawicznej identyfikacji zasobów sieciowych i monitorowania integralności infrastruktury w czasie rzeczywistym.

---

## ✨ Kluczowe Funkcje

### 🔍 Deep Scan Engine (Silnik ARP)
Wykorzystuje precyzyjne zapytania protokołu ARP do mapowania sieci. Pozwala na wykrycie hostów, które są skonfigurowane do ignorowania zapytań ICMP (Ping), co czyni go znacznie skuteczniejszym od standardowych rozwiązań.

### 🏷️ Moduł Inteligencji Sieciowej
- **Vendor Identification:** Rozpoznawanie producentów sprzętu na podstawie unikalnych identyfikatorów OUI (np. Apple, Samsung, Cisco, TP-Link).
- **Hostname Resolution:** Próba odczytu nazw sieciowych urządzeń poprzez mechanizm Reverse DNS.
- **OS Hinting:** Analiza sygnatury TTL (Time To Live) w celu predykcji systemu operacyjnego hosta (Linux/Unix vs Windows).

### 🛡️ System Monitorowania Integralności (Intruder Alert)
Automatyczne porównywanie aktualnego stanu sieci z bazą znanych urządzeń. System natychmiastowo flaguje nieznane adresy MAC jako potencjalne zagrożenie.

### 📈 Live Traffic & Port Sniper
- **Aktywność Sieciowa:** Monitorowanie ilości pakietów przesyłanych przez interfejs sieciowy (pkt/s).
- **Skanowanie Usług:** Sprawdzanie statusu krytycznych portów takich jak 22 (SSH), 80 (HTTP) czy 443 (HTTPS).

---

## 🛠️ Specyfikacja Techniczna

| Komponent | Technologia | Zastosowanie |
| :--- | :--- | :--- |
| **Język** | `Python 3.13+` | Logika biznesowa i przetwarzanie danych |
| **Silnik Sieciowy** | `Scapy` | Generowanie i przechwytywanie pakietów ARP/ICMP |
| **Interfejs** | `CustomTkinter` | Ghost UI z obsługą kanału Alpha (przezroczystość) |
| **Współbieżność** | `Threading` | Asynchroniczne skanowanie bez blokowania GUI |

---

## 🚀 Instalacja i Wdrożenie

1. **Wymagania:**
   - Sterownik [Npcap](https://npcap.com/) zainstalowany w trybie kompatybilności WinPcap.
   - Środowisko Python 3.13+.

2. **Przygotowanie środowiska:**
   ```bash
   pip install customtkinter scapy requests

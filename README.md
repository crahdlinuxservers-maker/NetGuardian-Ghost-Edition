# 👻 NetGuardian v2.1 - Ghost Edition
> **Zaawansowany skaner sieci LAN z interfejsem Glassmorphism**

NetGuardian to autorskie narzędzie do audytu i monitoringu sieci lokalnej, zaprojektowane z myślą o estetyce i funkcjonalności. Program łączy w sobie potęgę biblioteki `Scapy` z nowoczesnym, przezroczystym interfejsem użytkownika.

**Autor projektu:** Stanisław Kozioł

---

## 📸 Podgląd Interfejsu
![NetGuardian Screenshot](https://via.placeholder.com/1000x650.png?text=Wstaw+tutaj+zrzut+ekranu+ze+swojego+programu!)
*Zalecane: Wrzuć plik graficzny do repozytorium i podmień ten link, aby pokazać efekt Ghost Mode!*

---

## ⚡ Kluczowe Możliwości

### 🔍 Deep Scan Engine (Silnik ARP)
Program wykorzystuje niskopoziomowe zapytania ARP (Address Resolution Protocol), co pozwala wykryć urządzenia w sieci, które często ignorują standardowe zapytania PING (ICMP).

### 🏷️ Inteligencja Sieciowa
- **Vendor Lookup:** Identyfikacja producentów (Apple, Samsung, Tesla, TP-Link) na podstawie bazy OUI.
- **Hostname Resolution:** Automatyczne pobieranie nazw sieciowych urządzeń (DNS Reverse Lookup).
- **OS Hinting:** Analiza parametru TTL w celu rozpoznania systemu operacyjnego (Windows vs. Linux/Android).

### 🛡️ System Strażnika (Intruder Alert)
NetGuardian monitoruje zmiany w sieci. Jeśli podczas kolejnego skanu pojawi się nowy adres MAC, system oznaczy go statusem `!!! NOWY !!!` i wyśle ostrzeżenie na pasku statusu.

---

## 🛠 Technologia i Architektura

| Komponent | Technologia | Zastosowanie |
| :--- | :--- | :--- |
| **Interfejs** | `CustomTkinter` | Profesjonalny Dark Mode i Przezroczystość |
| **Silnik Sieciowy** | `Scapy` | Precyzyjne skanowanie ARP i Sniffing |
| **Współbieżność** | `Threading` | Płynna praca interfejsu podczas analizy sieci |
| **API** | `Requests` | Pobieranie danych o producentach |

---

## 📦 Instalacja i Uruchomienie

### Wymagania systemowe
1. **Windows 10/11**
2. **Npcap** (niezbędny do działania biblioteki Scapy) - [Pobierz Npcap](https://npcap.com/)
3. **Python 3.10+**

### Szybki start
1. Sklonuj to repozytorium:
   ```bash
   git clone [https://github.com/crahdlinuxservers-maker/NetGuardian-Ghost-Edition.git](https://github.com/crahdlinuxservers-maker/NetGuardian-Ghost-Edition.git)
   
2. cd NetGuardian-Ghost-Edition
3. pip install customtkinter scapy requests
4. python netguardian.py
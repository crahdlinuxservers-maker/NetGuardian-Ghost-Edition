# Changelog - NetGuardian

Wszystkie istotne zmiany w projekcie NetGuardian będą dokumentowane w tym pliku.

## [2.1] - Ghost Edition - 2024-05-22
### Dodano
- **Interfejs Ghost:** Wprowadzono pełną obsługę przezroczystości (Alpha Channel) z suwakiem.
- **Blokada Rozmiaru:** Ustalono stały rozmiar okna (1000x650) dla zachowania idealnego wyjustowania tabeli.
- **Detekcja Producenta:** Integracja z API macvendors.com.
- **System OS Hinting:** Rozpoznawanie systemów operacyjnych na podstawie odpowiedzi ICMP/TTL.
- **Hostname Lookup:** Automatyczne pobieranie nazw urządzeń z DNS lokalnego.
- **Eksport raportów:** Przycisk generujący czysty plik tekstowy z wynikami skanu.

### Zmieniono
- **Rebranding:** Przeniesienie informacji o autorze (Stanisław Kozioł) do dedykowanej sekcji w stopce.
- **Optymalizacja portów:** Skrócono timeout skanowania portów do 0.03s dla zwiększenia płynności.

## [1.5] - Stabilne Skanowanie
- Wprowadzenie wielowątkowości (threading), aby GUI nie zawieszało się podczas skanu.
- Dodanie monitora pakietów (Packet Sniffer) w czasie rzeczywistym.

## [1.0] - Pierwsze Wydanie
- Podstawowe skanowanie ARP i wykrywanie IP/MAC.
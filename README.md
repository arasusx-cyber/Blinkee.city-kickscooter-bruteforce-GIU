# Blinkee.city kickscooter
GUI IoT uart communication 
# ESC ↔ IOT UART Scanner GUI  
### Advanced UART protocol scanner for ESC and IOT reverse engineering  
### Zaawansowany skaner protokołu UART dla reverse engineering ESC i IOT

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![UART](https://img.shields.io/badge/UART-CRC32%20MPEG2-green)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## 🇬🇧 English
Python GUI tool for advanced UART communication analysis strictly between:

- ESC controller
- IOT module

Designed for:
- protocol mapping
- response fingerprinting
- ACK/NACK detection
- service command discovery
- handshake research
- full 4-byte brute-force scanning
- ESC ↔ IOT state analysis

---

## 🇵🇱 Polski
Pythonowe GUI do zaawansowanej analizy komunikacji UART wyłącznie pomiędzy:

- sterownikiem ESC
- modułem IOT

Projekt przeznaczony do:
- mapowania protokołu
- analizy wzorców odpowiedzi
- wykrywania ACK/NACK
- szukania komend serwisowych
- badania handshake
- pełnego brute-force 4-bajtowego payloadu
- analizy stanów ESC ↔ IOT

---

# ✨ Features / Funkcje

## 🔹 UART tools
- COM port selection
- custom baudrate
- raw 4B / 8B frame sending
- automatic CRC32 MPEG-2 generation
- live TX/RX logger
- heartbeat mode
- response logs
- no-confirm fast action mode

## 🔹 Smart autoscan
- full range: `00 00 00 00` → `FF FF FF FF`
- stop with progress save
- resume from saved position
- restart from zero
- automatic fast-forward on RX hit
- delay only on no response
- selected-range step autotest
- baseline response comparison

## 🔹 Response classification
- `NO_RX`
- `ACK_SAME`
- `ACK_DIFF`

This makes ESC ↔ IOT protocol discovery significantly faster.

---

# 📦 Frame format
```text
PAYLOAD(4B) + CRC32(4B)
```

## CRC
- CRC32 MPEG-2
- polynomial: `0x04C11DB7`
- init: `0xFFFFFFFF`
- no reflection
- xorout: `0x00000000`

---

# 🧪 Example / Przykład

## TX
```text
00 02 01 01 12 6D 58 1E
```

## RX
```text
80 02 01 01 B4 8B 65 03
```

Detected pattern:
```text
00 = request
80 = response ACK
```

---

# 🚀 Installation
```bash
pip install pyserial
```

Run:
```bash
python esc_uart_gui_tkinter_no_confirm.py
```

---

# 📁 Logs
Generated files:
- `esc_uart_gui_log.txt`
- `esc_uart_gui_response_changes.txt`
- `esc_uart_scan_progress.json`

---

# 🛣️ Roadmap
- [x] full 4-byte autoscan
- [x] scan progress resume
- [x] no-confirm fast mode
- [x] RX-based fast stepping
- [x] response fingerprinting
- [ ] automatic response clustering
- [ ] ACK response statistics
- [ ] protocol map generator
- [ ] session replay mode
- [ ] ESC ↔ IOT state graph
- [ ] response heatmap

---

# 🔬 Typical use cases
- ESC ↔ IOT reverse engineering
- service command discovery
- startup handshake analysis
- ESC unlock sequence research
- fleet ESC hardware diagnostics
- ACK response fingerprinting
- owned hardware protocol fuzzing

---

# ⚠️ Disclaimer
This project is intended only for:
- education
- diagnostics
- reverse engineering of owned hardware
- laboratory analysis
- protocol research

## 🇵🇱
Projekt przeznaczony wyłącznie do:
- edukacji
- diagnostyki
- reverse engineering własnego sprzętu
- testów laboratoryjnych
- analizy protokołów

The author is not responsible for unauthorized use on shared, rented, fleet or third-party devices.

Autor nie ponosi odpowiedzialności za użycie na urządzeniach współdzielonych, flotowych lub nienależących do użytkownika.

import json
import os
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
from pathlib import Path
from queue import Queue, Empty

import serial
import serial.tools.list_ports

BAUD_DEFAULT = 9600
TIMEOUT = 0.05
RX_FRAME_GAP = 0.05
HEARTBEAT_DEFAULT_MS = 300

LOG_FILE = Path("esc_uart_gui_log.txt")
RESP_LOG_FILE = Path("esc_uart_gui_response_changes.txt")
SCAN_PROGRESS_FILE = Path("esc_uart_scan_progress.json")
SMART_LOGS_DIR = Path("smart_family_logs")
GUI_MAX_LINES = 1000
WINDOW_STATE_FILE = Path("esc_uart_gui_window.json")
SMART_PROGRESS_FILE = Path("smart_scan_progress.json")


# ============================================================
# CRC / helpers
# ============================================================
def crc32_mpeg2(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= (b << 24)
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc & 0xFFFFFFFF


def build_frame(payload: bytes) -> bytes:
    # Protokół TX: CMD_HI CMD_LO LEN [VALUE...] + CRC32/MPEG-2.
    # Nie wysyłamy już 3-bajtowych ramek typu CMD CMD 00, bo w praktyce nie działają.
    # Nawet pusty odczyt idzie jako LEN=01 oraz VALUE=00, np. BAT: 01 02 01 00.
    if not (4 <= len(payload) <= 16):
        raise ValueError("Payload musi mieć od 4 do 16 bajtów: CMD CMD LEN VALUE...")
    return payload + crc32_mpeg2(payload).to_bytes(4, "big")


def hx(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def parse_hex(s: str) -> bytes:
    s = s.strip().replace("0x", "").replace(",", " ").replace(";", " ")
    parts = [p for p in s.split() if p]
    return bytes(int(p, 16) for p in parts)


def parse_payload4_text(s: str) -> bytes:
    raw = parse_hex(s)
    if len(raw) != 4:
        raise ValueError("Podaj dokładnie 4 bajty HEX, np. 00 00 00 00")
    return raw


def parse_payload4_16_text(s: str) -> bytes:
    raw = parse_hex(s)
    if not (4 <= len(raw) <= 16):
        raise ValueError("Podaj od 4 do 16 bajtów HEX, np. 01 02 01 00 albo 00 04 01 01")
    return raw


def payload4_to_int(payload4: bytes) -> int:
    if len(payload4) != 4:
        raise ValueError("Payload musi mieć 4 bajty")
    return int.from_bytes(payload4, "big")


def int_to_payload4(value: int) -> bytes:
    if not (0 <= value <= 0xFFFFFFFF):
        raise ValueError("Wartość poza zakresem 32-bit")
    return value.to_bytes(4, "big")


def ts() -> str:
    return time.strftime("%H:%M:%S")


def ts_ms() -> str:
    t = time.time()
    lt = time.localtime(t)
    ms = int((t - int(t)) * 1000)
    return time.strftime("%H:%M:%S", lt) + f".{ms:03d}"

def extract_ascii_runs(data: bytes, min_len: int = 4) -> list[str]:
    runs = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                runs.append(cur.decode("ascii", errors="ignore"))
            cur.clear()
    if len(cur) >= min_len:
        runs.append(cur.decode("ascii", errors="ignore"))
    return runs

def classify_responses(responses: list[bytes]) -> dict:
    if not responses:
        return {"score": 0, "kind": "NO_RX", "ascii": []}
    joined = b"".join(responses)
    ascii_runs = extract_ascii_runs(joined)
    first = responses[0]
    score = 1
    kind = "ACK"
    if len(first) != 8:
        score = max(score, 2)
        kind = "LONG_RX"
    if len(responses) > 1:
        score = max(score, 2)
        kind = "MULTI_RX"
    if ascii_runs:
        score = max(score, 5)
        kind = "ASCII"
    return {"score": score, "kind": kind, "ascii": ascii_runs}


def crc_ok_frame(frame: bytes) -> bool | None:
    if len(frame) < 7:
        return None
    payload = frame[:-4]
    got = int.from_bytes(frame[-4:], "big")
    return crc32_mpeg2(payload) == got


def decode_protocol_frame(frame: bytes) -> str:
    """Krótki opis RX/TX dla znanych ramek. Parser oparty o pole LEN.

    Ważne z logów:
    - RX z LEN=01 ma CRC32/MPEG-2 zgodne.
    - RX z LEN>01 niesie poprawne dane, ale końcówka nie pasuje do tej samej funkcji CRC.
      Dlatego dla długich RX pokazujemy CRC jako "CRC ?" zamiast traktować ramkę jako złą.
    """
    if len(frame) < 3:
        return ""

    parts: list[str] = []
    cmd0, cmd1, ln = frame[0], frame[1], frame[2]
    is_resp = bool(cmd0 & 0x80)

    data_start = 3
    data_end = min(len(frame), data_start + ln)
    data = frame[data_start:data_end]

    expected_total = 3 + ln + 4
    crc_status = ""
    if len(frame) >= expected_total:
        prefix = frame[:3 + ln]
        got_crc = frame[3 + ln:3 + ln + 4]
        exp_crc = crc32_mpeg2(prefix).to_bytes(4, "big")
        if got_crc == exp_crc:
            crc_status = "CRC OK"
        else:
            crc_status = "CRC ?"
        extra = frame[expected_total:]
        if extra:
            crc_status += f" +EXTRA={len(extra)}B"
    elif len(frame) >= 7:
        crc_status = "CRC ?/SHORT"

    if crc_status:
        parts.append(crc_status)

    # Znane odpowiedzi
    if frame.startswith(bytes([0x81, 0x02, 0x01])) and len(frame) >= 4:
        parts.append(f"BAT={frame[3]}%")

    if frame.startswith(bytes([0x80, 0x04, 0x02])) and len(frame) >= 5:
        raw = int.from_bytes(frame[3:5], "big")
        parts.append(f"SPD={raw / 10.0:.1f}km/h raw={raw}")

    if frame.startswith(bytes([0x80, 0x08, 0x02])) and len(frame) >= 5:
        raw = int.from_bytes(frame[3:5], "big")
        parts.append(f"STAT16=0x{raw:04X}")

    if frame.startswith(bytes([0x80, 0x01, 0x07])) and len(frame) >= 10:
        try:
            parts.append("MODEL=" + frame[3:10].decode("ascii", errors="ignore"))
        except Exception:
            pass

    if frame.startswith(bytes([0x82, 0x02, 0x07])) and len(frame) >= 10:
        try:
            parts.append("VER_A=" + frame[3:10].decode("ascii", errors="ignore"))
        except Exception:
            pass

    if frame.startswith(bytes([0x82, 0x03, 0x07])) and len(frame) >= 10:
        try:
            parts.append("VER_B=" + frame[3:10].decode("ascii", errors="ignore"))
        except Exception:
            pass

    if frame.startswith(bytes([0x8E, 0x00, 0x01])) and len(frame) >= 4:
        parts.append(f"PING={frame[3]}")

    if frame.startswith(bytes([0x8F, 0x02])) or frame.startswith(bytes([0x8F, 0x03])):
        parts.append("OTA/flash family response — do not probe")

    # Echo ACK / sterowanie
    if is_resp and ln == 1 and len(data) == 1:
        parts.append(f"DATA={data[0]:02X}")
    elif len(data) > 0:
        parts.append("DATA=" + hx(data))

    if is_resp:
        parts.append(f"RESP {cmd0:02X} {cmd1:02X} len={ln}")
    else:
        parts.append(f"REQ {cmd0:02X} {cmd1:02X} len={ln}")

    # ASCII tylko z pola danych, nie z CRC — inaczej CRC potrafi udawać tekst.
    ascii_runs = extract_ascii_runs(data, min_len=4)
    if ascii_runs:
        parts.append("ASCII=" + " | ".join(ascii_runs[:3]))

    return " ; ".join(parts)

def log_append(path: Path, line: str):
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def list_ports() -> list[str]:
    return [p.device for p in sorted(serial.tools.list_ports.comports(), key=lambda x: x.device)]


# 0F 02 / 0F 03 wygląda na rodzinę OTA/flash. Nie wysyłamy tego z GUI,
# bo może wejść w procedury aktualizacji i uszkodzić zawartość pamięci.
BLOCKED_CMD_PREFIXES = {
    bytes([0x0F, 0x02]): "0F 02 OTA/flash",
    bytes([0x0F, 0x03]): "0F 03 OTA/flash",
}


def blocked_payload_reason(payload: bytes) -> str | None:
    if len(payload) < 2:
        return None
    for prefix, reason in BLOCKED_CMD_PREFIXES.items():
        if payload.startswith(prefix):
            return reason
    return None


def is_blocked_payload(payload: bytes) -> bool:
    return blocked_payload_reason(payload) is not None


KNOWN = {
    # Format z logów:
    # CMD_HI CMD_LO LEN [VALUE...] + CRC32/MPEG-2
    # Wszystkie przyciski mają minimum 4 bajty: LEN oraz nawet pusty VALUE=00.

    # --- główne / najbardziej prawdopodobne ---
    "MODEL": bytes([0x00, 0x01, 0x01, 0x00]),
    "SPEED": bytes([0x00, 0x04, 0x01, 0x01]),  # potwierdzone z logu: RX 80 04 02 00 XX -> XX/10
    "STAT16": bytes([0x00, 0x08, 0x01, 0x00]),
    "BAT": bytes([0x01, 0x02, 0x01, 0x00]),    # potwierdzone: RX 81 02 01 XX -> XX%
    "WORD": bytes([0x01, 0x09, 0x01, 0x00]),
    "VER_A": bytes([0x02, 0x02, 0x01, 0x00]),
    "VER_B": bytes([0x02, 0x03, 0x01, 0x00]),
    "PING": bytes([0x0E, 0x00, 0x01, 0x00]),

    # --- warianty/sondy 4B z różnym ostatnim bajtem ---
    "MODEL_1": bytes([0x00, 0x01, 0x01, 0x01]),
    "MODEL_F": bytes([0x00, 0x01, 0x01, 0xFF]),
    "SPEED_0": bytes([0x00, 0x04, 0x01, 0x00]),
    "SPEED_F": bytes([0x00, 0x04, 0x01, 0xFF]),
    "STAT16_1": bytes([0x00, 0x08, 0x01, 0x01]),
    "STAT16_F": bytes([0x00, 0x08, 0x01, 0xFF]),
    "BAT_1": bytes([0x01, 0x02, 0x01, 0x01]),
    "BAT_2": bytes([0x01, 0x02, 0x01, 0x02]),
    "BAT_F": bytes([0x01, 0x02, 0x01, 0xFF]),
    "WORD_1": bytes([0x01, 0x09, 0x01, 0x01]),
    "WORD_F": bytes([0x01, 0x09, 0x01, 0xFF]),
    "VER_A_1": bytes([0x02, 0x02, 0x01, 0x01]),
    "VER_A_F": bytes([0x02, 0x02, 0x01, 0xFF]),
    "VER_B_1": bytes([0x02, 0x03, 0x01, 0x01]),
    "VER_B_F": bytes([0x02, 0x03, 0x01, 0xFF]),
    "PING_1": bytes([0x0E, 0x00, 0x01, 0x01]),
    "PING_F": bytes([0x0E, 0x00, 0x01, 0xFF]),

    # --- sterowanie 4B: CMD_HI CMD_LO LEN VALUE + CRC32/MPEG-2 ---
    "START": bytes([0x00, 0x02, 0x01, 0x01]),
    "STOP": bytes([0x00, 0x02, 0x01, 0x00]),
    "BUZZER_OFF": bytes([0x03, 0x03, 0x01, 0x00]),
    "BUZZER_ON": bytes([0x03, 0x03, 0x01, 0x01]),
    "AUX_OFF": bytes([0x03, 0x04, 0x01, 0x00]),
    "AUX_ON": bytes([0x03, 0x04, 0x01, 0x01]),
    "BAT_OPEN": bytes([0x03, 0x05, 0x01, 0x00]),
    "BAT_CLOSE": bytes([0x03, 0x05, 0x01, 0x01]),
}

KNOWN_LABELS = {
    # główne / potwierdzone
    "MODEL": "Model",
    "SPEED": "Speed",
    "STAT16": "Status 16",
    "BAT": "Battery",
    "WORD": "Status word",
    "VER_A": "Version A",
    "VER_B": "Version B",
    "PING": "Ping",

    # dodatkowe warianty / sondy
    "MODEL_1": "Model variant 01",
    "MODEL_F": "Model variant FF",
    "SPEED_0": "Speed variant 00",
    "SPEED_F": "Speed variant FF",
    "STAT16_1": "Status 16 variant 01",
    "STAT16_F": "Status 16 variant FF",
    "BAT_1": "Battery variant 01",
    "BAT_2": "Battery variant 02",
    "BAT_F": "Battery variant FF",
    "WORD_1": "Status word variant 01",
    "WORD_F": "Status word variant FF",
    "VER_A_1": "Version A variant 01",
    "VER_A_F": "Version A variant FF",
    "VER_B_1": "Version B variant 01",
    "VER_B_F": "Version B variant FF",
    "PING_1": "Ping variant 01",
    "PING_F": "Ping variant FF",

    # sterowanie
    "START": "Start",
    "STOP": "Stop",
    "BUZZER_ON": "Buzzer ON",
    "BUZZER_OFF": "Buzzer OFF",
    "AUX_ON": "AUX ON",
    "AUX_OFF": "AUX OFF",
    "BAT_OPEN": "Battery open",
    "BAT_CLOSE": "Battery close",
}


KNOWN_LABELS_I18N = {
    "PL": {
        "MODEL": "Model",
        "SPEED": "Prędkość",
        "STAT16": "Status 16",
        "BAT": "Bateria",
        "WORD": "Słowo statusu",
        "VER_A": "Wersja A",
        "VER_B": "Wersja B",
        "PING": "Ping",
        "MODEL_1": "Model wariant 01",
        "MODEL_F": "Model wariant FF",
        "SPEED_0": "Prędkość wariant 00",
        "SPEED_F": "Prędkość wariant FF",
        "STAT16_1": "Status 16 wariant 01",
        "STAT16_F": "Status 16 wariant FF",
        "BAT_1": "Bateria wariant 01",
        "BAT_2": "Bateria wariant 02",
        "BAT_F": "Bateria wariant FF",
        "WORD_1": "Słowo statusu wariant 01",
        "WORD_F": "Słowo statusu wariant FF",
        "VER_A_1": "Wersja A wariant 01",
        "VER_A_F": "Wersja A wariant FF",
        "VER_B_1": "Wersja B wariant 01",
        "VER_B_F": "Wersja B wariant FF",
        "PING_1": "Ping wariant 01",
        "PING_F": "Ping wariant FF",
        "START": "Start",
        "STOP": "Stop",
        "BUZZER_ON": "Buzzer ON",
        "BUZZER_OFF": "Buzzer OFF",
        "AUX_ON": "AUX ON",
        "AUX_OFF": "AUX OFF",
        "BAT_OPEN": "Otwórz baterię",
        "BAT_CLOSE": "Zamknij baterię",
    },
    "EN": {
        "MODEL": "Model",
        "SPEED": "Speed",
        "STAT16": "Status 16",
        "BAT": "Battery",
        "WORD": "Status word",
        "VER_A": "Version A",
        "VER_B": "Version B",
        "PING": "Ping",
        "MODEL_1": "Model variant 01",
        "MODEL_F": "Model variant FF",
        "SPEED_0": "Speed variant 00",
        "SPEED_F": "Speed variant FF",
        "STAT16_1": "Status 16 variant 01",
        "STAT16_F": "Status 16 variant FF",
        "BAT_1": "Battery variant 01",
        "BAT_2": "Battery variant 02",
        "BAT_F": "Battery variant FF",
        "WORD_1": "Status word variant 01",
        "WORD_F": "Status word variant FF",
        "VER_A_1": "Version A variant 01",
        "VER_A_F": "Version A variant FF",
        "VER_B_1": "Version B variant 01",
        "VER_B_F": "Version B variant FF",
        "PING_1": "Ping variant 01",
        "PING_F": "Ping variant FF",
        "START": "Start",
        "STOP": "Stop",
        "BUZZER_ON": "Buzzer ON",
        "BUZZER_OFF": "Buzzer OFF",
        "AUX_ON": "AUX ON",
        "AUX_OFF": "AUX OFF",
        "BAT_OPEN": "Battery open",
        "BAT_CLOSE": "Battery close",
    },
}

UI_TEXTS = {
    "PL": {
        "language": "Język:",
        "refresh": "Odśwież",
        "connect": "Połącz",
        "disconnect": "Rozłącz",
        "selftest": "Selftest",
        "open_general_log": "Otwórz log ogólny",
        "open_change_log": "Otwórz log zmian",
        "commands_box": "Szybkie komendy",
        "main_box": "Główne / potwierdzone",
        "extra_box": "Dodatkowe warianty / sondy",
        "control_box": "Sterowanie",
        "manual_box": "Ręczne wysyłanie",
        "manual_help": "4–16 bajtów przed CRC: CMD CMD LEN VALUE..., np. BAT 01 02 01 00 / SPEED 00 04 01 01",
        "send_auto": "Wyślij auto",
        "calc_crc": "Policz CRC",
        "heartbeat_box": "Heartbeat",
        "heartbeat_help": "Komenda heartbeat: START   |   Interwał ms:",
        "start_heartbeat": "Start heartbeat",
        "stop_heartbeat": "Stop heartbeat",
        "scan_box": "Autoscan 4-bajtowego zakresu",
        "from": "Od:",
        "to": "Do:",
        "response_window": "Okno odp. [s]:",
        "delay": "Delay [ms]:",
        "scan_start_new": "Start od nowa",
        "scan_stop_save": "Stop i zapisz",
        "resume": "Wznów",
        "load_progress": "Wczytaj zapisany postęp do pól",
        "smart_box": "Smart Tree Scan (family chopper)",
        "smart_window": "okno[s]:",
        "smart_delay": "delay[ms]:",
        "silent_values": "głuche values:",
        "silent_subcmd": "głuche subcmd:",
        "probe_values": "probe values:",
        "probe_jumps": "probe jumps:",
        "progress_every": "progress co N prób:",
        "smart_start": "Smart Start",
        "smart_stop": "Smart Stop",
        "autotest_box": "Autotest krokowy na wybranym zakresie",
        "not_started": "Nie uruchomiono",
        "range_start": "Start zakresu",
        "next_send": "Dalej + wyślij",
        "repeat": "Powtórz",
        "back": "Cofnij",
        "stop": "Stop",
        "usage_box": "Jak używać",
        "usage_text": "1. Przycisk Bateria wysyła 01 02 01 00 + CRC.\n2. Przycisk Prędkość wysyła 00 04 01 01 + CRC, a RX 80 04 02 XX YY dekoduję jako XXYY/10 km/h.\n3. Pozostałe odczyty są ustawione jako CMD CMD 01 00 + CRC, zgodnie z zasadą LEN + 00.\n4. Manual przyjmuje 4–16 bajtów przed CRC. 3-bajtowe zapytania są wycięte.\n5. Komendy 0F 02 / 0F 03 są zablokowane, bo wyglądają na OTA/flash.\n6. Scan, smart scan i manual pomijają/zatrzymują tę rodzinę, żeby nie ruszać pamięci.",
        "clear_log": "Wyczyść log w oknie",
        "save_log_as": "Zapisz log jako...",
        "connected": "POŁĄCZONO",
        "disconnected": "ROZŁĄCZONO",
        "autotest_stopped": "Zatrzymano",
    },
    "EN": {
        "language": "Language:",
        "refresh": "Refresh",
        "connect": "Connect",
        "disconnect": "Disconnect",
        "selftest": "Selftest",
        "open_general_log": "Open general log",
        "open_change_log": "Open change log",
        "commands_box": "Quick commands",
        "main_box": "Main / confirmed",
        "extra_box": "Extra variants / probes",
        "control_box": "Control",
        "manual_box": "Manual sending",
        "manual_help": "4–16 bytes before CRC: CMD CMD LEN VALUE..., e.g. BAT 01 02 01 00 / SPEED 00 04 01 01",
        "send_auto": "Send auto",
        "calc_crc": "Calculate CRC",
        "heartbeat_box": "Heartbeat",
        "heartbeat_help": "Heartbeat command: START   |   Interval ms:",
        "start_heartbeat": "Start heartbeat",
        "stop_heartbeat": "Stop heartbeat",
        "scan_box": "4-byte range autoscan",
        "from": "From:",
        "to": "To:",
        "response_window": "Response window [s]:",
        "delay": "Delay [ms]:",
        "scan_start_new": "Start from beginning",
        "scan_stop_save": "Stop and save",
        "resume": "Resume",
        "load_progress": "Load saved progress into fields",
        "smart_box": "Smart Tree Scan (family chopper)",
        "smart_window": "window[s]:",
        "smart_delay": "delay[ms]:",
        "silent_values": "silent values:",
        "silent_subcmd": "silent subcmd:",
        "probe_values": "probe values:",
        "probe_jumps": "probe jumps:",
        "progress_every": "progress every N tests:",
        "smart_start": "Smart Start",
        "smart_stop": "Smart Stop",
        "autotest_box": "Step-by-step autotest on selected range",
        "not_started": "Not started",
        "range_start": "Start range",
        "next_send": "Next + send",
        "repeat": "Repeat",
        "back": "Back",
        "stop": "Stop",
        "usage_box": "How to use",
        "usage_text": "1. The Battery button sends 01 02 01 00 + CRC.\n2. The Speed button sends 00 04 01 01 + CRC, and RX 80 04 02 XX YY is decoded as XXYY/10 km/h.\n3. Other read commands are set as CMD CMD 01 00 + CRC, following the LEN + 00 rule.\n4. Manual sending accepts 4–16 bytes before CRC. 3-byte queries are disabled.\n5. Commands 0F 02 / 0F 03 are blocked because they look like OTA/flash.\n6. Scan, smart scan and manual mode skip/block this family to avoid touching memory.",
        "clear_log": "Clear window log",
        "save_log_as": "Save log as...",
        "connected": "CONNECTED",
        "disconnected": "DISCONNECTED",
        "autotest_stopped": "Stopped",
    },
}

# Pierwszy rząd: rzeczy, które mają być pod ręką.
KNOWN_MAIN_BUTTONS = [
    "MODEL", "SPEED", "BAT", "WORD",
    "VER_A", "VER_B", "STAT16", "PING",
]

# Drugi blok: tylko warianty 4B, bez martwych ramek 3-bajtowych.
KNOWN_EXTRA_BUTTONS = [
    "MODEL_1", "MODEL_F",
    "SPEED_0", "SPEED_F",
    "STAT16_1", "STAT16_F",
    "BAT_1", "BAT_2", "BAT_F",
    "WORD_1", "WORD_F",
    "VER_A_1", "VER_A_F",
    "VER_B_1", "VER_B_F",
    "PING_1", "PING_F",
]

KNOWN_WRITE_BUTTONS = [
    "START", "STOP", "BUZZER_ON", "BUZZER_OFF",
    "AUX_ON", "AUX_OFF", "BAT_OPEN", "BAT_CLOSE",
]

ALL_KNOWN_BUTTONS = KNOWN_MAIN_BUTTONS + KNOWN_EXTRA_BUTTONS + KNOWN_WRITE_BUTTONS

def run_selftest():
    assert crc32_mpeg2(b"123456789") == 0x0376E6E7
    assert parse_hex("AA 55 01 01") == bytes([0xAA, 0x55, 0x01, 0x01])
    assert parse_hex("0xAA,0x55;0x01 0x01") == bytes([0xAA, 0x55, 0x01, 0x01])
    assert hx(bytes([0xAA, 0x55, 0x01, 0x01])) == "AA 55 01 01"
    f = build_frame(bytes([0xAA, 0x55, 0x01, 0x01]))
    assert len(f) == 8
    assert f[:4] == bytes([0xAA, 0x55, 0x01, 0x01])
    f_info = build_frame(bytes([0x01, 0x02, 0x01, 0x00]))
    assert len(f_info) == 8
    assert f_info[:4] == bytes([0x01, 0x02, 0x01, 0x00])
    assert parse_payload4_text("00 00 00 00") == bytes([0, 0, 0, 0])
    assert payload4_to_int(bytes([0x12, 0x34, 0x56, 0x78])) == 0x12345678
    assert int_to_payload4(0x12345678) == bytes([0x12, 0x34, 0x56, 0x78])
    assert KNOWN["BAT"] == bytes([0x01, 0x02, 0x01, 0x00])
    assert KNOWN["SPEED"] == bytes([0x00, 0x04, 0x01, 0x01])
    assert KNOWN["MODEL"] == bytes([0x00, 0x01, 0x01, 0x00])
    assert len(build_frame(KNOWN["BAT"])) == 8
    assert all(len(v) >= 4 for v in KNOWN.values())
    assert not any(k.endswith("_3B") for k in KNOWN)


class SerialWorker:
    def __init__(self, ui_callback):
        self.ser = None
        self.running = False
        self.rx_thread = None
        self.ui_callback = ui_callback
        self.rx_queue = Queue()
        self.hb_thread = None
        self.hb_stop = threading.Event()
        self.tx_lock = threading.Lock()

    def connect(self, port: str, baud: int):
        self.disconnect()
        self.ser = serial.Serial(port, baud, timeout=TIMEOUT)
        self.running = True
        self.rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self.rx_thread.start()

    def disconnect(self):
        self.stop_heartbeat()
        self.running = False
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None

    def is_connected(self) -> bool:
        return self.ser is not None and self.ser.is_open

    def _rx_loop(self):
        buf = bytearray()
        last_t = time.time()

        while self.running and self.ser:
            try:
                data = self.ser.read(256)
                now = time.time()

                if data:
                    buf.extend(data)
                    last_t = now
                elif buf and (now - last_t) > RX_FRAME_GAP:
                    frame = bytes(buf)
                    self.rx_queue.put(frame)
                    self.ui_callback("RX", frame, "")
                    buf.clear()
            except Exception as e:
                self.ui_callback("ERR", str(e).encode("utf-8", errors="ignore"), "RX")
                break

    def send_payload(self, payload: bytes, note: str = "") -> bytes:
        if not self.is_connected():
            raise RuntimeError("Brak połączenia z portem COM")
        reason = blocked_payload_reason(payload)
        if reason:
            raise RuntimeError(f"Zablokowano wysyłkę {hx(payload)} — {reason}. Te komendy mogą dotykać OTA/flash.")
        frame = build_frame(payload)
        with self.tx_lock:
            self.ser.write(frame)
            self.ser.flush()
        self.ui_callback("TX", frame, note)
        return frame

    def send_payload4(self, payload4: bytes, note: str = "") -> bytes:
        if len(payload4) != 4:
            raise ValueError("Ta funkcja wymaga dokładnie 4 bajtów payloadu")
        return self.send_payload(payload4, note)

    def send_payload_auto_crc(self, payload: bytes, note: str = "") -> bytes:
        return self.send_payload(payload, note)

    def send_raw8(self, frame8: bytes, note: str = "") -> bytes:
        if not self.is_connected():
            raise RuntimeError("Brak połączenia z portem COM")
        if len(frame8) != 8:
            raise ValueError("Raw frame musi mieć dokładnie 8 bajtów")
        reason = blocked_payload_reason(frame8[:4])
        if reason:
            raise RuntimeError(f"Zablokowano surową ramkę {hx(frame8)} — {reason}. Te komendy mogą dotykać OTA/flash.")
        with self.tx_lock:
            self.ser.write(frame8)
            self.ser.flush()
        self.ui_callback("TX", frame8, note)
        return frame8

    def clear_rx_queue(self):
        while True:
            try:
                self.rx_queue.get_nowait()
            except Empty:
                break

    def collect_responses(self, window_s: float) -> list[bytes]:
        end = time.time() + window_s
        out = []
        while time.time() < end:
            try:
                out.append(self.rx_queue.get(timeout=0.05))
            except Empty:
                pass
        return out

    def collect_responses_timed(self, window_s: float):
        start = time.perf_counter()
        end = time.time() + window_s
        out = []
        first_ms = None
        while time.time() < end:
            try:
                frame = self.rx_queue.get(timeout=0.005)
                out.append(frame)
                if first_ms is None:
                    first_ms = (time.perf_counter() - start) * 1000.0
            except Empty:
                pass
        return out, first_ms

    def start_heartbeat(self, payload4: bytes, interval_ms: int, note: str = "HB"):
        self.stop_heartbeat()
        self.hb_stop.clear()

        def worker():
            while not self.hb_stop.is_set():
                try:
                    self.send_payload4(payload4, note)
                except Exception:
                    break
                if self.hb_stop.wait(interval_ms / 1000.0):
                    break

        self.hb_thread = threading.Thread(target=worker, daemon=True)
        self.hb_thread.start()

    def stop_heartbeat(self):
        self.hb_stop.set()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ESC UART Safe GUI")
        self.geometry("1240x800")
        self.minsize(1040, 680)
        self.load_window_state()

        self.worker = SerialWorker(self.on_serial_event)
        self.safe_mode = tk.BooleanVar(value=True)
        self.baud_var = tk.StringVar(value=str(BAUD_DEFAULT))
        self.port_var = tk.StringVar()
        self.hb_interval_var = tk.StringVar(value=str(HEARTBEAT_DEFAULT_MS))
        self.manual_hex_var = tk.StringVar()

        self.scan_window_var = tk.StringVar(value="0.15")
        self.scan_from_var = tk.StringVar(value="00 00 00 00")
        self.scan_to_var = tk.StringVar(value="00 00 00 FF")
        self.scan_delay_var = tk.StringVar(value="10")

        self.scan_running = False
        self.scan_thread = None
        self.scan_stop_event = threading.Event()
        self.scan_saved_state = None

        self.smart_b0_from_var = tk.StringVar(value="00")
        self.smart_b0_to_var = tk.StringVar(value="10")
        self.smart_b1_from_var = tk.StringVar(value="00")
        self.smart_b1_to_var = tk.StringVar(value="10")
        self.smart_b2_from_var = tk.StringVar(value="00")
        self.smart_b2_to_var = tk.StringVar(value="FF")
        self.smart_window_var = tk.StringVar(value="0.120")
        self.smart_delay_var = tk.StringVar(value="25")
        self.smart_silent_values_var = tk.StringVar(value="10")
        self.smart_silent_subcmds_var = tk.StringVar(value="10")
        self.smart_probe_values_var = tk.StringVar(value="00 01 02 04 08 10 20 40 80 FF")
        self.smart_probe_jumps_var = tk.StringVar(value="08 10 20 40 80")
        self.smart_progress_every_var = tk.StringVar(value="50")
        self.smart_running = False
        self.smart_stop_event = threading.Event()
        self.smart_thread = None
        self.smart_run_token = 0

        self.autotest_running = False
        self.autotest_current = None
        self.autotest_from = None
        self.autotest_to = None

        self.lang_var = tk.StringVar(value="PL")
        self._i18n_widgets = []
        self.usage_label = None

        self._build_ui()
        self.refresh_ports()
        self.load_scan_progress(update_fields=False)
        self.update_ui_state()
        self.after(100, self._tick)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # --------------------------------------------------------
    # Scan progress persistence
    # --------------------------------------------------------
    def make_scan_state(self, current_value: int | None = None):
        start_payload = parse_payload4_text(self.scan_from_var.get().strip())
        end_payload = parse_payload4_text(self.scan_to_var.get().strip())
        start_value = payload4_to_int(start_payload)
        end_value = payload4_to_int(end_payload)
        if start_value > end_value:
            raise ValueError("Początek zakresu nie może być większy niż koniec")
        if current_value is None:
            current_value = start_value
        if current_value < start_value:
            current_value = start_value
        if current_value > end_value:
            current_value = end_value
        return {
            "start": hx(start_payload),
            "end": hx(end_payload),
            "start_int": start_value,
            "end_int": end_value,
            "current_int": current_value,
            "window_s": float(self.scan_window_var.get().strip()),
            "delay_ms": int(self.scan_delay_var.get().strip()),
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def save_scan_progress(self, current_value: int):
        state = self.make_scan_state(current_value)
        SCAN_PROGRESS_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
        self.scan_saved_state = state
        return state

    def load_scan_progress(self, update_fields: bool = True):
        if not SCAN_PROGRESS_FILE.exists():
            self.scan_saved_state = None
            return None
        try:
            state = json.loads(SCAN_PROGRESS_FILE.read_text(encoding="utf-8"))
            required = {"start", "end", "start_int", "end_int", "current_int", "window_s", "delay_ms"}
            if not required.issubset(state):
                raise ValueError("Brak wymaganych pól")
            self.scan_saved_state = state
            if update_fields:
                self.scan_from_var.set(state["start"])
                self.scan_to_var.set(state["end"])
                self.scan_window_var.set(str(state["window_s"]))
                self.scan_delay_var.set(str(state["delay_ms"]))
            return state
        except Exception:
            self.scan_saved_state = None
            return None

    # --------------------------------------------------------
    # UI
    # --------------------------------------------------------
    def tr(self, key: str) -> str:
        lang = self.lang_var.get() if hasattr(self, "lang_var") else "PL"
        return UI_TEXTS.get(lang, UI_TEXTS["PL"]).get(key, key)

    def i18n(self, widget, key: str):
        widget.configure(text=self.tr(key))
        self._i18n_widgets.append((widget, key))
        return widget

    def known_button_text(self, name: str) -> str:
        lang = self.lang_var.get() if hasattr(self, "lang_var") else "PL"
        return KNOWN_LABELS_I18N.get(lang, KNOWN_LABELS_I18N["PL"]).get(name, name)

    def apply_language(self, *_args):
        for widget, key in getattr(self, "_i18n_widgets", []):
            try:
                widget.configure(text=self.tr(key))
            except tk.TclError:
                pass
        for name in ALL_KNOWN_BUTTONS:
            btn = getattr(self, f"btn_known_{name}", None)
            if btn is not None:
                try:
                    btn.configure(text=self.known_button_text(name))
                except tk.TclError:
                    pass
        if getattr(self, "usage_label", None) is not None:
            try:
                self.usage_label.configure(text=self.tr("usage_text"))
            except tk.TclError:
                pass
        self._tick(update_only_once=True)

    def load_window_state(self):
        try:
            import json
            if WINDOW_STATE_FILE.exists():
                data = json.loads(WINDOW_STATE_FILE.read_text(encoding="utf-8"))
                geo = data.get("geometry")
                if geo:
                    self.geometry(geo)
        except Exception:
            pass

    def save_window_state(self):
        try:
            import json
            WINDOW_STATE_FILE.write_text(json.dumps({"geometry": self.geometry()}), encoding="utf-8")
        except Exception:
            pass

    def save_smart_progress(self, b0, b1, b2, b3):
        try:
            import json
            SMART_PROGRESS_FILE.write_text(json.dumps({
                "b0": b0, "b1": b1, "b2": b2, "b3": b3
            }), encoding="utf-8")
        except Exception:
            pass

    def load_smart_progress(self):
        try:
            import json
            if SMART_PROGRESS_FILE.exists():
                return json.loads(SMART_PROGRESS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return None
        return None

    def on_close(self):
        self.save_window_state()
        self.destroy()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="COM:").pack(side="left")
        self.port_combo = ttk.Combobox(top, textvariable=self.port_var, width=14, state="readonly")
        self.port_combo.pack(side="left", padx=(5, 8))

        self.i18n(ttk.Button(top, command=self.refresh_ports), "refresh").pack(side="left")
        ttk.Label(top, text="  Baud:").pack(side="left")
        ttk.Entry(top, textvariable=self.baud_var, width=8).pack(side="left", padx=(5, 8))
        self.btn_connect = self.i18n(ttk.Button(top, command=self.connect_port), "connect")
        self.btn_connect.pack(side="left")
        self.btn_disconnect = self.i18n(ttk.Button(top, command=self.disconnect_port), "disconnect")
        self.btn_disconnect.pack(side="left", padx=(6, 0))
        self.btn_selftest = self.i18n(ttk.Button(top, command=self.selftest_ui), "selftest")
        self.btn_selftest.pack(side="left", padx=(12, 0))

        self.i18n(ttk.Label(top), "language").pack(side="left", padx=(14, 4))
        self.lang_combo = ttk.Combobox(top, textvariable=self.lang_var, values=("PL", "EN"), width=5, state="readonly")
        self.lang_combo.pack(side="left")
        self.lang_combo.bind("<<ComboboxSelected>>", self.apply_language)

        self.i18n(ttk.Button(top, command=lambda: self.open_file(LOG_FILE)), "open_general_log").pack(side="right")
        self.i18n(ttk.Button(top, command=lambda: self.open_file(RESP_LOG_FILE)), "open_change_log").pack(side="right", padx=(0, 6))

        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Lewy panel ma dużo kontrolek. Na mniejszych ekranach zwykły Frame ucina dół,
        # więc pakujemy go w Canvas + pionowy scrollbar po prawej stronie.
        left_outer = ttk.Frame(body)
        right = ttk.Frame(body, padding=8)
        body.add(left_outer, weight=0)
        body.add(right, weight=1)

        left_canvas = tk.Canvas(left_outer, borderwidth=0, highlightthickness=0)
        left_scrollbar = ttk.Scrollbar(left_outer, orient="vertical", command=left_canvas.yview)
        left_canvas.configure(yscrollcommand=left_scrollbar.set)
        left_canvas.pack(side="left", fill="both", expand=True)
        left_scrollbar.pack(side="right", fill="y")

        left = ttk.Frame(left_canvas, padding=8)
        left_window = left_canvas.create_window((0, 0), window=left, anchor="nw")

        def _left_on_configure(_event=None):
            left_canvas.configure(scrollregion=left_canvas.bbox("all"))

        def _left_canvas_on_configure(event):
            # Trzyma szerokość zawartości równą szerokości canvasa, bez poziomego scrolla.
            left_canvas.itemconfigure(left_window, width=event.width)

        def _is_mouse_over_left_panel(event) -> bool:
            widget = self.winfo_containing(event.x_root, event.y_root)
            while widget is not None:
                if widget == left_canvas:
                    return True
                widget = getattr(widget, "master", None)
            return False

        def _left_mousewheel(event):
            if not _is_mouse_over_left_panel(event):
                return None
            if getattr(event, "num", None) == 4:
                left_canvas.yview_scroll(-1, "units")
            elif getattr(event, "num", None) == 5:
                left_canvas.yview_scroll(1, "units")
            else:
                delta = getattr(event, "delta", 0)
                if delta:
                    left_canvas.yview_scroll(int(-1 * (delta / 120)), "units")
            return "break"

        left.bind("<Configure>", _left_on_configure)
        left_canvas.bind("<Configure>", _left_canvas_on_configure)
        self.bind_all("<MouseWheel>", _left_mousewheel, add="+")
        self.bind_all("<Button-4>", _left_mousewheel, add="+")
        self.bind_all("<Button-5>", _left_mousewheel, add="+")

        conn_box = self.i18n(ttk.LabelFrame(left, padding=8), "commands_box")
        conn_box.pack(fill="x", pady=(0, 10))

        def make_button_grid(parent, names, cols=2):
            for i, name in enumerate(names):
                btn = ttk.Button(
                    parent,
                    text=self.known_button_text(name),
                    width=20,
                    command=lambda n=name: self.send_known(n),
                )
                btn.grid(row=i // cols, column=i % cols, sticky="ew", padx=3, pady=2)
                setattr(self, f"btn_known_{name}", btn)
            for c in range(cols):
                parent.columnconfigure(c, weight=1)

        main_box = self.i18n(ttk.LabelFrame(conn_box, padding=4), "main_box")
        main_box.pack(fill="x", pady=(0, 6))
        make_button_grid(main_box, KNOWN_MAIN_BUTTONS, cols=2)

        extra_box = self.i18n(ttk.LabelFrame(conn_box, padding=4), "extra_box")
        extra_box.pack(fill="x", pady=(0, 6))
        make_button_grid(extra_box, KNOWN_EXTRA_BUTTONS, cols=2)

        write_box = self.i18n(ttk.LabelFrame(conn_box, padding=4), "control_box")
        write_box.pack(fill="x")
        make_button_grid(write_box, KNOWN_WRITE_BUTTONS, cols=2)

        manual = self.i18n(ttk.LabelFrame(left, padding=8), "manual_box")
        manual.pack(fill="x", pady=(0, 10))
        self.i18n(ttk.Label(manual), "manual_help").pack(anchor="w")
        ttk.Entry(manual, textvariable=self.manual_hex_var).pack(fill="x", pady=6)

        row = ttk.Frame(manual)
        row.pack(fill="x")
        self.btn_send_manual = self.i18n(ttk.Button(row, command=self.send_manual_auto), "send_auto")
        self.btn_send_manual.pack(side="left", expand=True, fill="x")
        self.btn_show_crc = self.i18n(ttk.Button(row, command=self.show_crc), "calc_crc")
        self.btn_show_crc.pack(side="left", expand=True, fill="x", padx=(6, 0))

        hb = self.i18n(ttk.LabelFrame(left, padding=8), "heartbeat_box")
        hb.pack(fill="x", pady=(0, 10))
        self.i18n(ttk.Label(hb), "heartbeat_help").pack(anchor="w")
        ttk.Entry(hb, textvariable=self.hb_interval_var).pack(fill="x", pady=6)
        row = ttk.Frame(hb)
        row.pack(fill="x")
        self.btn_hb_start = self.i18n(ttk.Button(row, command=lambda: self.start_hb("START")), "start_heartbeat")
        self.btn_hb_start.pack(side="left", expand=True, fill="x")
        self.btn_hb_stop = self.i18n(ttk.Button(row, command=self.stop_hb), "stop_heartbeat")
        self.btn_hb_stop.pack(side="left", expand=True, fill="x", padx=(6, 0))

        scan = self.i18n(ttk.LabelFrame(left, padding=8), "scan_box")
        scan.pack(fill="x", pady=(0, 10))

        row = ttk.Frame(scan)
        row.pack(fill="x", pady=(0, 6))
        self.i18n(ttk.Label(row), "from").pack(side="left")
        ttk.Entry(row, textvariable=self.scan_from_var, width=18).pack(side="left", padx=(4, 10))
        self.i18n(ttk.Label(row), "to").pack(side="left")
        ttk.Entry(row, textvariable=self.scan_to_var, width=18).pack(side="left", padx=(4, 0))

        row = ttk.Frame(scan)
        row.pack(fill="x", pady=(0, 6))
        self.i18n(ttk.Label(row), "response_window").pack(side="left")
        ttk.Entry(row, textvariable=self.scan_window_var, width=8).pack(side="left", padx=(4, 10))
        self.i18n(ttk.Label(row), "delay").pack(side="left")
        ttk.Entry(row, textvariable=self.scan_delay_var, width=8).pack(side="left", padx=(4, 0))

        row = ttk.Frame(scan)
        row.pack(fill="x", pady=(0, 6))
        self.btn_scan_start = self.i18n(ttk.Button(row, command=self.scan_start_new), "scan_start_new")
        self.btn_scan_start.pack(side="left", expand=True, fill="x")
        self.btn_scan_stop = self.i18n(ttk.Button(row, command=self.scan_stop_save), "scan_stop_save")
        self.btn_scan_stop.pack(side="left", expand=True, fill="x", padx=4)
        self.btn_scan_resume = self.i18n(ttk.Button(row, command=self.scan_resume), "resume")
        self.btn_scan_resume.pack(side="left", expand=True, fill="x")


        self.btn_scan_load = self.i18n(ttk.Button(scan, command=self.scan_load_to_fields), "load_progress")
        self.btn_scan_load.pack(fill="x")

        smart = self.i18n(ttk.LabelFrame(left, padding=8), "smart_box")
        smart.pack(fill="x", pady=(0, 10))

        row = ttk.Frame(smart)
        row.pack(fill="x", pady=(0, 6))
        ttk.Label(row, text="B0:").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_b0_from_var, width=4).pack(side="left", padx=(4, 2))
        ttk.Label(row, text="→").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_b0_to_var, width=4).pack(side="left", padx=(2, 10))
        ttk.Label(row, text="B1:").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_b1_from_var, width=4).pack(side="left", padx=(4, 2))
        ttk.Label(row, text="→").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_b1_to_var, width=4).pack(side="left", padx=(2, 0))

        row = ttk.Frame(smart)
        row.pack(fill="x", pady=(0, 6))
        ttk.Label(row, text="B2:").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_b2_from_var, width=4).pack(side="left", padx=(4, 2))
        ttk.Label(row, text="→").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_b2_to_var, width=4).pack(side="left", padx=(2, 10))
        self.i18n(ttk.Label(row), "smart_window").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_window_var, width=6).pack(side="left", padx=(4, 8))
        self.i18n(ttk.Label(row), "smart_delay").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_delay_var, width=6).pack(side="left", padx=(4, 0))

        row = ttk.Frame(smart)
        row.pack(fill="x", pady=(0, 6))
        self.i18n(ttk.Label(row), "silent_values").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_silent_values_var, width=6).pack(side="left", padx=(4, 10))
        self.i18n(ttk.Label(row), "silent_subcmd").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_silent_subcmds_var, width=6).pack(side="left", padx=(4, 0))

        row = ttk.Frame(smart)
        row.pack(fill="x", pady=(0, 6))
        self.i18n(ttk.Label(row), "probe_values").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_probe_values_var).pack(side="left", fill="x", expand=True, padx=(4, 0))

        row = ttk.Frame(smart)
        row.pack(fill="x", pady=(0, 6))
        self.i18n(ttk.Label(row), "probe_jumps").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_probe_jumps_var).pack(side="left", fill="x", expand=True, padx=(4, 0))

        row = ttk.Frame(smart)
        row.pack(fill="x", pady=(0, 6))
        self.i18n(ttk.Label(row), "progress_every").pack(side="left")
        ttk.Entry(row, textvariable=self.smart_progress_every_var, width=8).pack(side="left", padx=(4, 0))

        row = ttk.Frame(smart)
        row.pack(fill="x")
        self.btn_smart_start = self.i18n(ttk.Button(row, command=self.smart_scan_start), "smart_start")
        self.btn_smart_start.pack(side="left", expand=True, fill="x")
        self.btn_smart_stop = self.i18n(ttk.Button(row, command=self.smart_scan_stop), "smart_stop")
        self.btn_smart_stop.pack(side="left", expand=True, fill="x", padx=(6, 0))

        auto = self.i18n(ttk.LabelFrame(left, padding=8), "autotest_box")
        auto.pack(fill="x", pady=(0, 10))
        self.autotest_label = self.i18n(ttk.Label(auto), "not_started")
        self.autotest_label.pack(anchor="w", pady=(0, 6))

        row = ttk.Frame(auto)
        row.pack(fill="x")
        self.btn_autotest_start = self.i18n(ttk.Button(row, command=self.autotest_start), "range_start")
        self.btn_autotest_start.pack(side="left", expand=True, fill="x")
        self.btn_autotest_next = self.i18n(ttk.Button(row, command=self.autotest_next), "next_send")
        self.btn_autotest_next.pack(side="left", expand=True, fill="x", padx=4)
        self.btn_autotest_repeat = self.i18n(ttk.Button(row, command=self.autotest_repeat), "repeat")
        self.btn_autotest_repeat.pack(side="left", expand=True, fill="x")

        row2 = ttk.Frame(auto)
        row2.pack(fill="x", pady=(6, 0))
        self.btn_autotest_back = self.i18n(ttk.Button(row2, command=self.autotest_back), "back")
        self.btn_autotest_back.pack(side="left", expand=True, fill="x")
        self.btn_autotest_stop = self.i18n(ttk.Button(row2, command=self.autotest_stop), "stop")
        self.btn_autotest_stop.pack(side="left", expand=True, fill="x", padx=(6, 0))

        info = self.i18n(ttk.LabelFrame(left, padding=8), "usage_box")
        info.pack(fill="both", expand=True)

        msg = (
            "1. Przycisk BAT wysyła 01 02 01 00 + CRC.\n"
            "2. Przycisk SPD wysyła 00 04 01 01 + CRC, a RX 80 04 02 XX YY dekoduję jako XXYY/10 km/h.\n"
            "3. Pozostałe odczyty są ustawione jako CMD CMD 01 00 + CRC, zgodnie z zasadą LEN + 00.\n"
            "4. Manual przyjmuje 4–16 bajtów przed CRC. 3-bajtowe zapytania są wycięte.\n"
            "5. Komendy 0F 02 / 0F 03 są zablokowane, bo wyglądają na OTA/flash.\n"
            "6. Scan, smart scan i manual pomijają/zatrzymują tę rodzinę, żeby nie ruszać pamięci."
        )
        self.usage_label = ttk.Label(info, text=self.tr("usage_text"), justify="left")
        self.usage_label.pack(anchor="w")

        right_top = ttk.Frame(right)
        right_top.pack(fill="x")
        self.i18n(ttk.Button(right_top, command=self.clear_log), "clear_log").pack(side="left")
        self.i18n(ttk.Button(right_top, command=self.save_log_as), "save_log_as").pack(side="left", padx=6)

        self.log_text = ScrolledText(right, wrap="word", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, pady=(8, 0))
        self.log_text.configure(state="disabled")

    # --------------------------------------------------------
    # Utility UI
    # --------------------------------------------------------
    def _log_ui_direct(self, line: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n")
        total_lines = int(self.log_text.index("end-1c").split(".")[0])
        if total_lines > GUI_MAX_LINES:
            self.log_text.delete("1.0", f"{total_lines - GUI_MAX_LINES}.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def log_ui(self, line: str):
        if threading.current_thread() is not threading.main_thread():
            self.after(0, lambda l=line: self._log_ui_direct(l))
            return
        self._log_ui_direct(line)

    def clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def save_log_as(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("All files", "*.*")]
        )
        if not path:
            return
        content = self.log_text.get("1.0", "end")
        Path(path).write_text(content, encoding="utf-8")
        messagebox.showinfo("OK", f"Zapisano: {path}")

    def open_file(self, path: Path):
        if not path.exists():
            messagebox.showwarning("Brak pliku", f"Plik jeszcze nie istnieje:\n{path}")
            return
        try:
            import os
            os.startfile(path)
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def ask_safe(self, text: str) -> bool:
        return True

    def selftest_ui(self):
        try:
            run_selftest()
            messagebox.showinfo("Selftest", "Selftest OK")
        except Exception as e:
            messagebox.showerror("Selftest", str(e))

    def scan_load_to_fields(self):
        state = self.load_scan_progress(update_fields=True)
        if state:
            self.log_ui(f"[{ts()}] INFO Załadowano zapisany postęp: {state['start']} -> {state['end']} @ {int_to_payload4(state['current_int']).hex().upper()}")
        else:
            messagebox.showwarning("Brak", "Brak zapisanego postępu scanu")

    def _set_btn_state(self, widget, enabled: bool):
        try:
            widget.configure(state=('normal' if enabled else 'disabled'))
        except Exception:
            pass

    def update_ui_state(self):
        connected = self.worker.is_connected()
        scanning = self.scan_running
        smarting = self.smart_running
        busy = scanning or smarting
        autotest = self.autotest_running

        self._set_btn_state(self.btn_connect, not connected and not busy)
        self._set_btn_state(self.btn_disconnect, connected and not busy)
        self._set_btn_state(self.btn_selftest, not busy)

        # Szybkie komendy zostają dostępne także w trakcie scanów.
        for name in ALL_KNOWN_BUTTONS:
            self._set_btn_state(getattr(self, f"btn_known_{name}"), connected)

        # Ręczne wysyłanie też zostaje aktywne podczas testów.
        self._set_btn_state(self.btn_send_manual, connected)
        self._set_btn_state(self.btn_show_crc, True)

        self._set_btn_state(self.btn_hb_start, connected and not busy)
        self._set_btn_state(self.btn_hb_stop, connected)

        self._set_btn_state(self.btn_scan_start, connected and not busy)
        self._set_btn_state(self.btn_scan_stop, scanning)
        self._set_btn_state(self.btn_scan_resume, connected and not busy)
        self._set_btn_state(self.btn_scan_load, not busy)

        self._set_btn_state(self.btn_smart_start, connected and not busy)
        self._set_btn_state(self.btn_smart_stop, smarting)

        self._set_btn_state(self.btn_autotest_start, connected and not busy)
        self._set_btn_state(self.btn_autotest_next, connected and autotest and not busy)
        self._set_btn_state(self.btn_autotest_repeat, connected and autotest and not busy)
        self._set_btn_state(self.btn_autotest_back, autotest and not busy)
        self._set_btn_state(self.btn_autotest_stop, autotest)

    # --------------------------------------------------------
    # Serial event bridge
    # --------------------------------------------------------
    def on_serial_event(self, kind: str, data: bytes, note: str):
        if kind in ("RX", "TX"):
            line = f"[{ts()}] {kind} {hx(data)}"
            desc = decode_protocol_frame(data)
            if desc:
                line += f" | {desc}"
            if note:
                line += f" | {note}"
            log_append(LOG_FILE, line)
        else:
            line = f"[{ts()}] {kind} {data.decode(errors='ignore')}"
        self.after(0, lambda l=line: self.log_ui(l))

    def _tick(self, update_only_once: bool = False):
        status = self.tr("connected") if self.worker.is_connected() else self.tr("disconnected")
        self.title(f"ESC UART Safe GUI — {status}")
        self.update_ui_state()
        if not update_only_once:
            self.after(250, self._tick)

    # --------------------------------------------------------
    # Connect / disconnect
    # --------------------------------------------------------
    def refresh_ports(self):
        ports = list_ports()
        self.port_combo["values"] = ports
        if ports and not self.port_var.get():
            self.port_var.set(ports[0])

    def connect_port(self):
        port = self.port_var.get().strip()
        if not port:
            messagebox.showwarning("Brak COM", "Wybierz port COM")
            return
        try:
            baud = int(self.baud_var.get().strip())
            self.worker.connect(port, baud)
            self.log_ui(f"[{ts()}] INFO Połączono z {port} @ {baud}")
            self.update_ui_state()
        except Exception as e:
            messagebox.showerror("Błąd połączenia", str(e))

    def disconnect_port(self):
        self.worker.disconnect()
        self.log_ui(f"[{ts()}] INFO Rozłączono")
        self.update_ui_state()

    # --------------------------------------------------------
    # Send actions
    # --------------------------------------------------------
    def send_known(self, name: str):
        if name in ("BAT_OPEN", "BAT_CLOSE"):
            if not self.ask_safe(f"Wysłać {name}? To może zmienić stan blokady baterii."):
                return
        try:
            self.worker.send_payload_auto_crc(KNOWN[name], name)
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def send_manual_auto(self):
        text = self.manual_hex_var.get().strip()
        if not text:
            return
        try:
            raw = parse_hex(text)
            if 4 <= len(raw) <= 16:
                reason = blocked_payload_reason(raw)
                if reason:
                    messagebox.showerror("Zablokowano OTA/flash", f"Nie wysyłam {hx(raw)} — {reason}. To może ruszyć OTA/flash i uszkodzić pamięć.")
                    return
                if not self.ask_safe(f"Wyślij {len(raw)} bajtów z auto CRC?\n{hx(raw)}"):
                    return
                self.worker.send_payload_auto_crc(raw, f"manual_auto_crc_{len(raw)}")
            else:
                messagebox.showwarning("Zła długość", "Podaj 4–16 bajtów payloadu dla auto CRC; minimum to CMD CMD LEN VALUE")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def show_crc(self):
        text = self.manual_hex_var.get().strip()
        try:
            raw = parse_hex(text)
            if not (4 <= len(raw) <= 16):
                messagebox.showwarning("Zła długość", "Tu liczymy CRC dla payloadu 4–16 bajtów")
                return
            reason = blocked_payload_reason(raw)
            if reason:
                messagebox.showerror("Zablokowano OTA/flash", f"Nie podpowiadam ramki CRC dla {hx(raw)} — {reason}. To może ruszyć OTA/flash i uszkodzić pamięć.")
                return
            frame = build_frame(raw)
            messagebox.showinfo("Pełna ramka", hx(frame))
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    # --------------------------------------------------------
    # Heartbeat
    # --------------------------------------------------------
    def start_hb(self, name: str):
        try:
            ms = int(self.hb_interval_var.get().strip())
            if ms <= 0:
                raise ValueError("Interwał musi być > 0")
            if not self.ask_safe(f"Uruchomić heartbeat {name} co {ms} ms?"):
                return
            self.worker.start_heartbeat(KNOWN[name], ms, f"HB:{name}")
            self.log_ui(f"[{ts()}] INFO Heartbeat ON: START co {ms} ms")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def stop_hb(self):
        self.worker.stop_heartbeat()
        self.log_ui(f"[{ts()}] INFO Heartbeat OFF")

    # --------------------------------------------------------
    # Scan ranges
    # --------------------------------------------------------
    def parse_scan_form(self):
        try:
            start_payload = parse_payload4_text(self.scan_from_var.get().strip())
            end_payload = parse_payload4_text(self.scan_to_var.get().strip())
            start_value = payload4_to_int(start_payload)
            end_value = payload4_to_int(end_payload)
            window_s = float(self.scan_window_var.get().strip())
            delay_ms = int(self.scan_delay_var.get().strip())
        except ValueError as e:
            raise ValueError(
                f"Błędne dane zakresu: {e}.\n"
                "Wpisuj pełne 4 bajty HEX, np. 00 00 00 00 do 00 00 00 FF."
            )

        if start_value > end_value:
            raise ValueError("Początek zakresu nie może być większy niż koniec")
        if delay_ms < 0 or window_s < 0:
            raise ValueError("Delay i okno odpowiedzi nie mogą być ujemne")

        return start_value, end_value, window_s, delay_ms

    def scan_start_new(self):
        if not self.ask_safe("Uruchomić autoscan od nowa dla podanego zakresu?"):
            return
        try:
            start_value, end_value, window_s, delay_ms = self.parse_scan_form()
        except Exception as e:
            messagebox.showerror("Błąd", str(e))
            return
        self.start_scan_worker(start_value, end_value, window_s, delay_ms)

    def scan_resume(self):
        if self.scan_running:
            messagebox.showwarning("Scan aktywny", "Autoscan już działa")
            return

        state = self.load_scan_progress(update_fields=True)
        if not state:
            messagebox.showwarning("Brak postępu", "Nie ma zapisanego postępu do wznowienia")
            return

        current_value = int(state["current_int"])
        end_value = int(state["end_int"])
        if current_value > end_value:
            messagebox.showinfo("Koniec", "Zapisany scan jest już zakończony")
            return

        if not self.ask_safe(
            f"Wznowić autoscan od {hx(int_to_payload4(current_value))} do {state['end']}?"
        ):
            return

        self.start_scan_worker(current_value, end_value, float(state["window_s"]), int(state["delay_ms"]))

    def scan_stop_save(self):
        if not self.scan_running:
            try:
                start_value, _, _, _ = self.parse_scan_form()
                state = self.save_scan_progress(start_value)
                self.log_ui(f"[{ts()}] INFO Scan nie działał. Zapisano punkt startowy: {hx(int_to_payload4(state['current_int']))}")
            except Exception as e:
                messagebox.showerror("Błąd", str(e))
            return

        self.scan_stop_event.set()
        self.log_ui(f"[{ts()}] INFO Żądanie zatrzymania autoscanu wysłane")
        self.update_ui_state()

    def start_scan_worker(self, start_value: int, end_value: int, window_s: float, delay_ms: int):
        if self.scan_running:
            messagebox.showwarning("Scan aktywny", "Najpierw zatrzymaj obecny autoscan")
            return

        self.scan_running = True
        self.scan_stop_event.clear()
        self.update_ui_state()

        def worker():
            baseline = None
            hits = 0
            total = 0
            current_value = start_value
            self.save_scan_progress(current_value)
            self.log_ui(
                f"[{ts()}] INFO SCAN START from={hx(int_to_payload4(start_value))} to={hx(int_to_payload4(end_value))}"
            )
            try:
                while current_value <= end_value:
                    if self.scan_stop_event.is_set():
                        self.save_scan_progress(current_value)
                        self.log_ui(f"[{ts()}] INFO SCAN STOP at {hx(int_to_payload4(current_value))}")
                        return

                    payload = int_to_payload4(current_value)
                    reason = blocked_payload_reason(payload)
                    if reason:
                        self.log_ui(f"[{ts()}] SKIP {hx(payload)} — {reason}")
                        next_value = current_value + 1
                        if next_value <= end_value:
                            self.save_scan_progress(next_value)
                        current_value += 1
                        continue
                    total += 1
                    try:
                        self.worker.clear_rx_queue()
                        frame = self.worker.send_payload4(payload, f"scan:{hx(payload)}")
                        responses, first_ms = self.worker.collect_responses_timed(window_s)
                        sign = tuple(hx(r) for r in responses)

                        if baseline is None:
                            baseline = sign

                        if sign != baseline:
                            hits += 1
                            log_append(RESP_LOG_FILE, "=" * 70)
                            log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} CMD {hx(payload)}")
                            log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} TX  {hx(frame)}")
                            if first_ms is not None:
                                log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} RX_TIME {first_ms:.2f} ms")
                            if responses:
                                for i, r in enumerate(responses, start=1):
                                    log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} RX{i:02d} {hx(r)}")
                            else:
                                log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} RX <brak odpowiedzi>")
                            self.log_ui(f"[{ts()}] DIFF {hx(payload)}")

                        next_value = current_value + 1
                        if next_value <= end_value:
                            self.save_scan_progress(next_value)
                        else:
                            self.save_scan_progress(end_value)

                        if delay_ms > 0 and self.scan_stop_event.wait(delay_ms / 1000.0):
                            next_to_resume = min(current_value + 1, end_value)
                            self.save_scan_progress(next_to_resume)
                            self.log_ui(f"[{ts()}] INFO SCAN STOP at {hx(int_to_payload4(next_to_resume))}")
                            return
                        current_value += 1
                    except Exception as e:
                        self.save_scan_progress(current_value)
                        self.log_ui(f"[{ts()}] ERR scan {e}")
                        return

                done_state = self.save_scan_progress(end_value)
                done_state["current_int"] = end_value + 1
                SCAN_PROGRESS_FILE.write_text(json.dumps(done_state, indent=2), encoding="utf-8")
                self.scan_saved_state = done_state
                self.log_ui(f"[{ts()}] INFO SCAN DONE hits={hits} total={total}")
            finally:
                self.scan_running = False
                self.scan_thread = None
                self.scan_stop_event.clear()
                self.after(0, self.update_ui_state)

        self.scan_thread = threading.Thread(target=worker, daemon=True)
        self.scan_thread.start()

    # --------------------------------------------------------
    # Autotest step-by-step on selected range
    # --------------------------------------------------------
    def autotest_prepare_range(self):
        start_value, end_value, _, _ = self.parse_scan_form()
        self.autotest_from = start_value
        self.autotest_to = end_value
        if self.autotest_current is None or not (start_value <= self.autotest_current <= end_value):
            self.autotest_current = start_value

    def autotest_start(self):
        try:
            self.autotest_prepare_range()
        except Exception as e:
            messagebox.showerror("Błąd", str(e))
            return
        self.autotest_running = True
        self.autotest_current = self.autotest_from
        self._autotest_show()
        self.update_ui_state()

    def autotest_stop(self):
        self.autotest_running = False
        self.autotest_label.config(text=self.tr("autotest_stopped"))
        self.update_ui_state()

    def _autotest_show(self):
        if not self.autotest_running or self.autotest_current is None:
            self.autotest_label.config(text=self.tr("not_started"))
            return
        payload = int_to_payload4(self.autotest_current)
        total = (self.autotest_to - self.autotest_from) + 1
        index = (self.autotest_current - self.autotest_from) + 1
        if self.lang_var.get() == "EN":
            label = f"Step {index}/{total}: [{hx(payload)}]  range: {hx(int_to_payload4(self.autotest_from))} -> {hx(int_to_payload4(self.autotest_to))}"
        else:
            label = f"Krok {index}/{total}: [{hx(payload)}]  zakres: {hx(int_to_payload4(self.autotest_from))} -> {hx(int_to_payload4(self.autotest_to))}"
        self.autotest_label.config(text=label)

    def autotest_fire_current(self):
        if not self.autotest_running or self.autotest_current is None:
            return

        payload = int_to_payload4(self.autotest_current)
        reason = blocked_payload_reason(payload)
        if reason:
            self.log_ui(f"[{ts()}] SKIP autotest {hx(payload)} — {reason}")
            return

        def worker():
            try:
                self.worker.clear_rx_queue()
                frame = self.worker.send_payload4(payload, f"autotest:{hx(payload)}")
                responses, first_ms = self.worker.collect_responses_timed(0.45)

                log_append(RESP_LOG_FILE, "=" * 70)
                log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} AUTOTEST {hx(payload)}")
                log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} TX {hx(frame)}")
                if first_ms is not None:
                    log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} RX_TIME {first_ms:.2f} ms")
                if responses:
                    for i, r in enumerate(responses, start=1):
                        log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} RX{i:02d} {hx(r)}")
                else:
                    log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} RX <brak odpowiedzi>")
            except Exception as e:
                self.log_ui(f"[{ts()}] ERR autotest {e}")

        threading.Thread(target=worker, daemon=True).start()

    def autotest_next(self):
        if not self.autotest_running:
            self.autotest_start()
        self.autotest_fire_current()
        if self.autotest_current < self.autotest_to:
            self.autotest_current += 1
        self._autotest_show()

    def autotest_repeat(self):
        if not self.autotest_running:
            self.autotest_start()
        self.autotest_fire_current()
        self._autotest_show()

    def autotest_back(self):
        if not self.autotest_running:
            self.autotest_start()
            return
        if self.autotest_current > self.autotest_from:
            self.autotest_current -= 1
        self._autotest_show()

    # --------------------------------------------------------
    # Smart family logs / smart tree scan
    # --------------------------------------------------------
    def parse_hex_byte(self, value: str) -> int:
        return int(value.strip(), 16)

    def parse_hex_list(self, value: str) -> list[int]:
        raw = parse_hex(value)
        return list(raw)

    def family_dir(self, b0: int, b1: int) -> Path:
        path = SMART_LOGS_DIR / f"{b0:02X}_{b1:02X}"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def family_paths(self, b0: int, b1: int) -> dict:
        root = self.family_dir(b0, b1)
        return {
            "hits": root / f"{b0:02X}_{b1:02X}_xx_xx_hits.log",
            "interesting": root / f"{b0:02X}_{b1:02X}_xx_xx_interesting.log",
            "progress": root / f"{b0:02X}_{b1:02X}_xx_xx_progress.json",
            "summary": root / f"{b0:02X}_{b1:02X}_xx_xx_summary.json",
        }

    def write_family_progress(self, b0: int, b1: int, data: dict):
        paths = self.family_paths(b0, b1)
        paths["progress"].write_text(json.dumps(data, indent=2), encoding="utf-8")

    def append_family_hit(self, b0: int, b1: int, payload: bytes, frame: bytes, first_ms, responses: list[bytes], cls: dict):
        paths = self.family_paths(b0, b1)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_append(paths["hits"], "=" * 70)
        log_append(paths["hits"], f"{stamp} CMD {hx(payload)}")
        log_append(paths["hits"], f"{stamp} TX  {hx(frame)}")
        if first_ms is not None:
            log_append(paths["hits"], f"{stamp} RX_TIME {first_ms:.2f} ms")
        log_append(paths["hits"], f"{stamp} KIND {cls['kind']} SCORE {cls['score']}")
        if cls["ascii"]:
            log_append(paths["hits"], f"{stamp} ASCII {' | '.join(cls['ascii'])}")
        if responses:
            for i, r in enumerate(responses, start=1):
                log_append(paths["hits"], f"{stamp} RX{i:02d} {hx(r)}")
        else:
            log_append(paths["hits"], f"{stamp} RX <brak odpowiedzi>")
        if cls["score"] >= 2 or cls["ascii"]:
            log_append(paths["interesting"], "=" * 70)
            log_append(paths["interesting"], f"{stamp} CMD {hx(payload)}")
            log_append(paths["interesting"], f"{stamp} KIND {cls['kind']} SCORE {cls['score']}")
            if cls["ascii"]:
                log_append(paths["interesting"], f"{stamp} ASCII {' | '.join(cls['ascii'])}")
            if responses:
                for i, r in enumerate(responses, start=1):
                    log_append(paths["interesting"], f"{stamp} RX{i:02d} {hx(r)}")

    def test_payload_once(self, payload: bytes, window_s: float, delay_ms: int = 0):
        reason = blocked_payload_reason(payload)
        if reason:
            self.log_ui(f"[{ts()}] SKIP smart {hx(payload)} — {reason}")
            return b"", [], None, {"score": 0, "kind": "SKIPPED_OTA", "ascii": []}
        self.worker.clear_rx_queue()
        frame = self.worker.send_payload4(payload, f"scan:{hx(payload)}")
        responses, first_ms = self.worker.collect_responses_timed(window_s)
        cls = classify_responses(responses)
        if delay_ms > 0:
            self.smart_stop_event.wait(delay_ms / 1000.0)
        return frame, responses, first_ms, cls

    def smart_progress_log(self, total_tested: int, total_hits: int, b0: int, b1: int, b2: int, b3: int, note: str = "SMART progress"):
        self.log_ui(f"[{ts()}] {note} tested={total_tested} hits={total_hits} at={b0:02X} {b1:02X} {b2:02X} {b3:02X}")

    def smart_worker_should_stop(self, run_token: int) -> bool:
        return self.smart_stop_event.is_set() or (run_token != self.smart_run_token)

    def smart_scan_stop(self):
        if self.smart_running or (self.smart_thread and self.smart_thread.is_alive()):
            self.smart_stop_event.set()
            self.smart_run_token += 1
            self.log_ui(f"[{ts()}] INFO Smart scan stop requested")
            self.update_ui_state()

    def smart_scan_start(self):
        if self.smart_running or (self.smart_thread and self.smart_thread.is_alive()):
            messagebox.showwarning("Smart scan aktywny", "Smart scan już działa")
            return
        try:
            b0_from = self.parse_hex_byte(self.smart_b0_from_var.get())
            b0_to = self.parse_hex_byte(self.smart_b0_to_var.get())
            b1_from = self.parse_hex_byte(self.smart_b1_from_var.get())
            b1_to = self.parse_hex_byte(self.smart_b1_to_var.get())
            b2_from = self.parse_hex_byte(self.smart_b2_from_var.get())
            b2_to = self.parse_hex_byte(self.smart_b2_to_var.get())
            window_s = float(self.smart_window_var.get().strip())
            delay_ms = int(self.smart_delay_var.get().strip())
            silent_values = int(self.smart_silent_values_var.get().strip())
            silent_subcmds = int(self.smart_silent_subcmds_var.get().strip())
            probe_values = self.parse_hex_list(self.smart_probe_values_var.get())
            probe_jumps = self.parse_hex_list(self.smart_probe_jumps_var.get())
            progress_every = int(self.smart_progress_every_var.get().strip())
        except Exception as e:
            messagebox.showerror("Błąd smart scan", str(e))
            return

        if not (0 <= b0_from <= b0_to <= 0xFF and 0 <= b1_from <= b1_to <= 0xFF and 0 <= b2_from <= b2_to <= 0xFF):
            messagebox.showerror("Błąd smart scan", "Zakresy muszą być w HEX 00..FF i od <= do")
            return

        progress = self.load_smart_progress()
        resume_tuple = None
        if progress:
            resume_tuple = (
                progress.get("b0", b0_from),
                progress.get("b1", b1_from),
                progress.get("b2", b2_from),
                progress.get("b3", 0),
            )

        self.smart_run_token += 1
        run_token = self.smart_run_token
        self.smart_running = True
        self.smart_stop_event.clear()
        self.update_ui_state()

        def worker():
            SMART_LOGS_DIR.mkdir(exist_ok=True)
            total_tested = 0
            total_hits = 0
            last_alive_log = time.time()
            self.log_ui(f"[{ts()}] SMART SCAN START B0={b0_from:02X}-{b0_to:02X} B1={b1_from:02X}-{b1_to:02X} B2={b2_from:02X}-{b2_to:02X} win={window_s}s delay={delay_ms}ms")
            try:
                start_b0 = resume_tuple[0] if resume_tuple else b0_from
                for b0 in range(start_b0, b0_to + 1):
                    start_b1 = resume_tuple[1] if (resume_tuple and b0 == resume_tuple[0]) else b1_from
                    for b1 in range(start_b1, b1_to + 1):
                        if self.smart_worker_should_stop(run_token):
                            return
                        reason = blocked_payload_reason(bytes([b0, b1, 0x01, 0x00]))
                        if reason:
                            self.log_ui(f"[{ts()}] SMART FAMILY {b0:02X} {b1:02X} SKIPPED — {reason}")
                            continue
                        self.log_ui(f"[{ts()}] SMART FAMILY {b0:02X} {b1:02X} START")
                        dead_b2_streak = 0
                        family_tested = 0
                        family_hits = 0
                        family_alive_b2 = []
                        start_b2 = resume_tuple[2] if (resume_tuple and b0 == resume_tuple[0] and b1 == resume_tuple[1]) else b2_from
                        for b2 in range(start_b2, b2_to + 1):
                            if self.smart_worker_should_stop(run_token):
                                return
                            self.log_ui(f"[{ts()}] SMART SUBCMD {b0:02X} {b1:02X} {b2:02X} START")
                            checked_values = set()
                            b2_hits = 0
                            # probe values
                            for b3 in probe_values:
                                if b3 in checked_values:
                                    continue
                                checked_values.add(b3)
                                payload = bytes([b0, b1, b2, b3])
                                self.save_smart_progress(b0, b1, b2, b3)
                                frame, responses, first_ms, cls = self.test_payload_once(payload, window_s, delay_ms)
                                total_tested += 1
                                family_tested += 1
                                if progress_every > 0 and (total_tested % progress_every) == 0:
                                    self.smart_progress_log(total_tested, total_hits, b0, b1, b2, b3)
                                if (time.time() - last_alive_log) >= 1.5:
                                    self.smart_progress_log(total_tested, total_hits, b0, b1, b2, b3, "SMART alive")
                                    last_alive_log = time.time()
                                if cls["score"] > 0:
                                    total_hits += 1
                                    family_hits += 1
                                    b2_hits += 1
                                    self.append_family_hit(b0, b1, payload, frame, first_ms, responses, cls)
                                    self.log_ui(f"[{ts()}] HIT {hx(payload)} {cls['kind']} {('/'.join(cls['ascii'])) if cls['ascii'] else ''}")
                            if b2_hits == 0:
                                dead_b2_streak += 1
                                self.log_ui(f"[{ts()}] SMART SUBCMD {b0:02X} {b1:02X} {b2:02X} DEAD streak={dead_b2_streak}")
                                self.write_family_progress(b0, b1, {
                                    "b0": f"{b0:02X}", "b1": f"{b1:02X}", "last_b2": f"{b2:02X}",
                                    "family_tested": family_tested, "family_hits": family_hits,
                                    "alive_b2": [f"{x:02X}" for x in family_alive_b2],
                                    "status": "dead_b2"
                                })
                                if dead_b2_streak >= silent_subcmds and family_hits > 0:
                                    self.log_ui(f"[{ts()}] SMART FAMILY {b0:02X} {b1:02X} STOP after {dead_b2_streak} głuchych subcmd")
                                    break
                                continue

                            family_alive_b2.append(b2)
                            dead_b2_streak = 0

                            # adaptive full B3 scan for alive b2
                            current = 0
                            silent_count = 0
                            while current <= 0xFF:
                                if self.smart_worker_should_stop(run_token):
                                    return
                                if current in checked_values:
                                    current += 1
                                    continue
                                payload = bytes([b0, b1, b2, current])
                                self.save_smart_progress(b0, b1, b2, current)
                                frame, responses, first_ms, cls = self.test_payload_once(payload, window_s, delay_ms)
                                checked_values.add(current)
                                total_tested += 1
                                family_tested += 1
                                if progress_every > 0 and (total_tested % progress_every) == 0:
                                    self.smart_progress_log(total_tested, total_hits, b0, b1, b2, current)
                                if (time.time() - last_alive_log) >= 1.5:
                                    self.smart_progress_log(total_tested, total_hits, b0, b1, b2, current, "SMART alive")
                                    last_alive_log = time.time()
                                if cls["score"] > 0:
                                    total_hits += 1
                                    family_hits += 1
                                    b2_hits += 1
                                    silent_count = 0
                                    self.append_family_hit(b0, b1, payload, frame, first_ms, responses, cls)
                                    self.log_ui(f"[{ts()}] HIT {hx(payload)} {cls['kind']} {('/'.join(cls['ascii'])) if cls['ascii'] else ''}")
                                    current += 1
                                    continue

                                silent_count += 1
                                if silent_count < silent_values:
                                    current += 1
                                    continue

                                found = None
                                for jump in probe_jumps:
                                    probe = min(0xFF, current + jump)
                                    if probe in checked_values or probe <= current:
                                        continue
                                    probe_payload = bytes([b0, b1, b2, probe])
                                    pframe, presponses, pfirst_ms, pcls = self.test_payload_once(probe_payload, window_s, delay_ms)
                                    checked_values.add(probe)
                                    total_tested += 1
                                    family_tested += 1
                                    if progress_every > 0 and (total_tested % progress_every) == 0:
                                        self.smart_progress_log(total_tested, total_hits, b0, b1, b2, probe, "SMART probe")
                                    if (time.time() - last_alive_log) >= 1.5:
                                        self.smart_progress_log(total_tested, total_hits, b0, b1, b2, probe, "SMART alive")
                                        last_alive_log = time.time()
                                    if pcls["score"] > 0:
                                        total_hits += 1
                                        family_hits += 1
                                        b2_hits += 1
                                        self.append_family_hit(b0, b1, probe_payload, pframe, pfirst_ms, presponses, pcls)
                                        self.log_ui(f"[{ts()}] PROBE-HIT {hx(probe_payload)} {pcls['kind']}")
                                        found = probe
                                        break

                                if found is None:
                                    break

                                for fill in range(current + 1, found):
                                    if fill in checked_values:
                                        continue
                                    fill_payload = bytes([b0, b1, b2, fill])
                                    fframe, fresponses, ffirst_ms, fcls = self.test_payload_once(fill_payload, window_s, delay_ms)
                                    checked_values.add(fill)
                                    total_tested += 1
                                    family_tested += 1
                                    if progress_every > 0 and (total_tested % progress_every) == 0:
                                        self.smart_progress_log(total_tested, total_hits, b0, b1, b2, fill, "SMART fill")
                                    if (time.time() - last_alive_log) >= 1.5:
                                        self.smart_progress_log(total_tested, total_hits, b0, b1, b2, fill, "SMART alive")
                                        last_alive_log = time.time()
                                    if fcls["score"] > 0:
                                        total_hits += 1
                                        family_hits += 1
                                        b2_hits += 1
                                        self.append_family_hit(b0, b1, fill_payload, fframe, ffirst_ms, fresponses, fcls)
                                        self.log_ui(f"[{ts()}] FILL-HIT {hx(fill_payload)} {fcls['kind']}")
                                current = found + 1
                                silent_count = 0

                            self.write_family_progress(b0, b1, {
                                "b0": f"{b0:02X}", "b1": f"{b1:02X}", "last_b2": f"{b2:02X}",
                                "family_tested": family_tested, "family_hits": family_hits,
                                "alive_b2": [f"{x:02X}" for x in family_alive_b2],
                                "status": "alive_b2_done"
                            })

                        paths = self.family_paths(b0, b1)
                        paths["summary"].write_text(json.dumps({
                            "b0": f"{b0:02X}",
                            "b1": f"{b1:02X}",
                            "family_tested": family_tested,
                            "family_hits": family_hits,
                            "alive_b2": [f"{x:02X}" for x in family_alive_b2],
                        }, indent=2), encoding="utf-8")
                        self.log_ui(f"[{ts()}] SMART FAMILY {b0:02X} {b1:02X} DONE tested={family_tested} hits={family_hits}")
                self.log_ui(f"[{ts()}] SMART SCAN DONE tested={total_tested} hits={total_hits}")
            except Exception as e:
                self.log_ui(f"[{ts()}] ERR smart scan {e}")
            finally:
                if self.smart_stop_event.is_set() or run_token != self.smart_run_token:
                    self.log_ui(f"[{ts()}] SMART SCAN STOPPED tested={total_tested} hits={total_hits}")
                self.smart_running = False
                self.smart_thread = None
                self.smart_stop_event.clear()
                self.after(0, self.update_ui_state)

        self.smart_thread = threading.Thread(target=worker, daemon=True)
        self.smart_thread.start()


if __name__ == "__main__":
    run_selftest()
    app = App()
    app.mainloop()

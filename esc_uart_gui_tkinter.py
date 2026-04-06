import json
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
from pathlib import Path
from queue import Queue, Empty

import serial
import serial.tools.list_ports

BAUD_DEFAULT = 38400
TIMEOUT = 0.05
RX_FRAME_GAP = 0.05
HEARTBEAT_DEFAULT_MS = 300

LOG_FILE = Path("esc_uart_gui_log.txt")
RESP_LOG_FILE = Path("esc_uart_gui_response_changes.txt")
SCAN_PROGRESS_FILE = Path("esc_uart_scan_progress.json")


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


def build_frame(payload4: bytes) -> bytes:
    if len(payload4) != 4:
        raise ValueError("Payload musi mieć dokładnie 4 bajty")
    return payload4 + crc32_mpeg2(payload4).to_bytes(4, "big")


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


def log_append(path: Path, line: str):
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def list_ports() -> list[str]:
    return [p.device for p in sorted(serial.tools.list_ports.comports(), key=lambda x: x.device)]


KNOWN = {
    "START": bytes([0x00, 0x02, 0x01, 0x01]),
    "STOP": bytes([0x00, 0x02, 0x01, 0x00]),
    "BAT_OPEN": bytes([0x03, 0x05, 0x01, 0x00]),
    "BAT_CLOSE": bytes([0x03, 0x05, 0x01, 0x01]),
    "MODE1": bytes([0x00, 0x03, 0x01, 0x01]),
    "MODE0": bytes([0x00, 0x03, 0x01, 0x00]),
}


def run_selftest():
    assert crc32_mpeg2(b"123456789") == 0x0376E6E7
    assert parse_hex("AA 55 01 01") == bytes([0xAA, 0x55, 0x01, 0x01])
    assert parse_hex("0xAA,0x55;0x01 0x01") == bytes([0xAA, 0x55, 0x01, 0x01])
    assert hx(bytes([0xAA, 0x55, 0x01, 0x01])) == "AA 55 01 01"
    f = build_frame(bytes([0xAA, 0x55, 0x01, 0x01]))
    assert len(f) == 8
    assert f[:4] == bytes([0xAA, 0x55, 0x01, 0x01])
    assert parse_payload4_text("00 00 00 00") == bytes([0, 0, 0, 0])
    assert payload4_to_int(bytes([0x12, 0x34, 0x56, 0x78])) == 0x12345678
    assert int_to_payload4(0x12345678) == bytes([0x12, 0x34, 0x56, 0x78])


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

    def send_payload4(self, payload4: bytes, note: str = "") -> bytes:
        if not self.is_connected():
            raise RuntimeError("Brak połączenia z portem COM")
        frame = build_frame(payload4)
        with self.tx_lock:
            self.ser.write(frame)
            self.ser.flush()
        self.ui_callback("TX", frame, note)
        return frame

    def send_raw8(self, frame8: bytes, note: str = "") -> bytes:
        if not self.is_connected():
            raise RuntimeError("Brak połączenia z portem COM")
        if len(frame8) != 8:
            raise ValueError("Raw frame musi mieć dokładnie 8 bajtów")
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

        self.worker = SerialWorker(self.on_serial_event)
        self.safe_mode = tk.BooleanVar(value=True)
        self.baud_var = tk.StringVar(value=str(BAUD_DEFAULT))
        self.port_var = tk.StringVar()
        self.hb_interval_var = tk.StringVar(value=str(HEARTBEAT_DEFAULT_MS))
        self.manual_hex_var = tk.StringVar()

        self.scan_window_var = tk.StringVar(value="0.45")
        self.scan_from_var = tk.StringVar(value="00 00 00 00")
        self.scan_to_var = tk.StringVar(value="00 00 00 FF")
        self.scan_delay_var = tk.StringVar(value="200")

        self.scan_running = False
        self.scan_thread = None
        self.scan_stop_event = threading.Event()
        self.scan_saved_state = None

        self.autotest_running = False
        self.autotest_current = None
        self.autotest_from = None
        self.autotest_to = None

        self._build_ui()
        self.refresh_ports()
        self.load_scan_progress(update_fields=False)
        self.after(100, self._tick)

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
    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="COM:").pack(side="left")
        self.port_combo = ttk.Combobox(top, textvariable=self.port_var, width=14, state="readonly")
        self.port_combo.pack(side="left", padx=(5, 8))

        ttk.Button(top, text="Odśwież", command=self.refresh_ports).pack(side="left")
        ttk.Label(top, text="  Baud:").pack(side="left")
        ttk.Entry(top, textvariable=self.baud_var, width=8).pack(side="left", padx=(5, 8))
        ttk.Button(top, text="Połącz", command=self.connect_port).pack(side="left")
        ttk.Button(top, text="Rozłącz", command=self.disconnect_port).pack(side="left", padx=(6, 0))
        ttk.Button(top, text="Selftest", command=self.selftest_ui).pack(side="left", padx=(12, 0))

        ttk.Button(top, text="Otwórz log ogólny", command=lambda: self.open_file(LOG_FILE)).pack(side="right")
        ttk.Button(top, text="Otwórz log zmian", command=lambda: self.open_file(RESP_LOG_FILE)).pack(side="right", padx=(0, 6))

        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        left = ttk.Frame(body, padding=8)
        right = ttk.Frame(body, padding=8)
        body.add(left, weight=0)
        body.add(right, weight=1)

        conn_box = ttk.LabelFrame(left, text="Szybkie komendy", padding=8)
        conn_box.pack(fill="x", pady=(0, 10))

        for i, name in enumerate(["START", "STOP", "BAT_OPEN", "BAT_CLOSE", "MODE1", "MODE0"]):
            ttk.Button(conn_box, text=name, command=lambda n=name: self.send_known(n)).grid(
                row=i // 2, column=i % 2, sticky="ew", padx=4, pady=4
            )
        conn_box.columnconfigure(0, weight=1)
        conn_box.columnconfigure(1, weight=1)

        manual = ttk.LabelFrame(left, text="Ręczne wysyłanie", padding=8)
        manual.pack(fill="x", pady=(0, 10))
        ttk.Label(manual, text="4 bajty lub 8 bajtów hex:").pack(anchor="w")
        ttk.Entry(manual, textvariable=self.manual_hex_var).pack(fill="x", pady=6)

        row = ttk.Frame(manual)
        row.pack(fill="x")
        ttk.Button(row, text="Wyślij auto", command=self.send_manual_auto).pack(side="left", expand=True, fill="x")
        ttk.Button(row, text="Policz CRC", command=self.show_crc).pack(side="left", expand=True, fill="x", padx=(6, 0))

        hb = ttk.LabelFrame(left, text="Heartbeat", padding=8)
        hb.pack(fill="x", pady=(0, 10))
        ttk.Label(hb, text="Interwał ms:").pack(anchor="w")
        ttk.Entry(hb, textvariable=self.hb_interval_var).pack(fill="x", pady=6)
        row = ttk.Frame(hb)
        row.pack(fill="x")
        ttk.Button(row, text="HB START", command=lambda: self.start_hb("START")).pack(side="left", expand=True, fill="x")
        ttk.Button(row, text="HB STOP", command=self.stop_hb).pack(side="left", expand=True, fill="x", padx=(6, 0))

        scan = ttk.LabelFrame(left, text="Autoscan 4-bajtowego zakresu", padding=8)
        scan.pack(fill="x", pady=(0, 10))

        row = ttk.Frame(scan)
        row.pack(fill="x", pady=(0, 6))
        ttk.Label(row, text="Od:").pack(side="left")
        ttk.Entry(row, textvariable=self.scan_from_var, width=18).pack(side="left", padx=(4, 10))
        ttk.Label(row, text="Do:").pack(side="left")
        ttk.Entry(row, textvariable=self.scan_to_var, width=18).pack(side="left", padx=(4, 0))

        row = ttk.Frame(scan)
        row.pack(fill="x", pady=(0, 6))
        ttk.Label(row, text="Okno odp. [s]:").pack(side="left")
        ttk.Entry(row, textvariable=self.scan_window_var, width=8).pack(side="left", padx=(4, 10))
        ttk.Label(row, text="Delay [ms]:").pack(side="left")
        ttk.Entry(row, textvariable=self.scan_delay_var, width=8).pack(side="left", padx=(4, 0))

        row = ttk.Frame(scan)
        row.pack(fill="x", pady=(0, 6))
        ttk.Button(row, text="Start od nowa", command=self.scan_start_new).pack(side="left", expand=True, fill="x")
        ttk.Button(row, text="Stop i zapisz", command=self.scan_stop_save).pack(side="left", expand=True, fill="x", padx=4)
        ttk.Button(row, text="Wznów", command=self.scan_resume).pack(side="left", expand=True, fill="x")

        ttk.Button(scan, text="Wczytaj zapisany postęp do pól", command=self.scan_load_to_fields).pack(fill="x")

        auto = ttk.LabelFrame(left, text="Autotest krokowy na wybranym zakresie", padding=8)
        auto.pack(fill="x", pady=(0, 10))
        self.autotest_label = ttk.Label(auto, text="Nie uruchomiono")
        self.autotest_label.pack(anchor="w", pady=(0, 6))

        row = ttk.Frame(auto)
        row.pack(fill="x")
        ttk.Button(row, text="Start zakresu", command=self.autotest_start).pack(side="left", expand=True, fill="x")
        ttk.Button(row, text="Dalej + wyślij", command=self.autotest_next).pack(side="left", expand=True, fill="x", padx=4)
        ttk.Button(row, text="Powtórz", command=self.autotest_repeat).pack(side="left", expand=True, fill="x")

        row2 = ttk.Frame(auto)
        row2.pack(fill="x", pady=(6, 0))
        ttk.Button(row2, text="Cofnij", command=self.autotest_back).pack(side="left", expand=True, fill="x")
        ttk.Button(row2, text="Stop", command=self.autotest_stop).pack(side="left", expand=True, fill="x", padx=(6, 0))

        info = ttk.LabelFrame(left, text="Jak używać", padding=8)
        info.pack(fill="both", expand=True)

        msg = (
            "1. Zakres autoscanu wpisujesz jako pełne 4 bajty, np. 00 00 00 00 do FF FF FF FF.\n"
            "2. Stop i zapisz zapisuje aktualny punkt do pliku JSON, a Wznów startuje od tego miejsca.\n"
            "3. Start od nowa ignoruje poprzedni postęp i leci od pola \"Od\".\n"
            "4. Autotest krokowy działa teraz na tym samym zakresie, nie na stałej liście komend.\n"
            "5. Log zmian zapisuje tylko odpowiedzi różne od bazowej odpowiedzi z pierwszej próbki."
        )
        ttk.Label(info, text=msg, justify="left").pack(anchor="w")

        right_top = ttk.Frame(right)
        right_top.pack(fill="x")
        ttk.Button(right_top, text="Wyczyść log w oknie", command=self.clear_log).pack(side="left")
        ttk.Button(right_top, text="Zapisz log jako...", command=self.save_log_as).pack(side="left", padx=6)

        self.log_text = ScrolledText(right, wrap="word", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, pady=(8, 0))
        self.log_text.configure(state="disabled")

    # --------------------------------------------------------
    # Utility UI
    # --------------------------------------------------------
    def log_ui(self, line: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

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

    # --------------------------------------------------------
    # Serial event bridge
    # --------------------------------------------------------
    def on_serial_event(self, kind: str, data: bytes, note: str):
        if kind in ("RX", "TX"):
            line = f"[{ts()}] {kind} {hx(data)}"
            if note:
                line += f" | {note}"
            log_append(LOG_FILE, line)
        else:
            line = f"[{ts()}] {kind} {data.decode(errors='ignore')}"
        self.after(0, lambda l=line: self.log_ui(l))

    def _tick(self):
        status = "POŁĄCZONO" if self.worker.is_connected() else "ROZŁĄCZONO"
        self.title(f"ESC UART Safe GUI — {status}")
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
        except Exception as e:
            messagebox.showerror("Błąd połączenia", str(e))

    def disconnect_port(self):
        self.worker.disconnect()
        self.log_ui(f"[{ts()}] INFO Rozłączono")

    # --------------------------------------------------------
    # Send actions
    # --------------------------------------------------------
    def send_known(self, name: str):
        if name in ("BAT_OPEN", "BAT_CLOSE"):
            if not self.ask_safe(f"Wysłać {name}? To może zmienić stan blokady baterii."):
                return
        try:
            self.worker.send_payload4(KNOWN[name], name)
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def send_manual_auto(self):
        text = self.manual_hex_var.get().strip()
        if not text:
            return
        try:
            raw = parse_hex(text)
            if len(raw) == 4:
                if not self.ask_safe(f"Wyślij 4 bajty z auto CRC?\n{hx(raw)}"):
                    return
                self.worker.send_payload4(raw, "manual4")
            elif len(raw) == 8:
                if not self.ask_safe(f"Wyślij surowe 8 bajtów?\n{hx(raw)}"):
                    return
                self.worker.send_raw8(raw, "manual8")
            else:
                messagebox.showwarning("Zła długość", "Podaj 4 albo 8 bajtów hex")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))

    def show_crc(self):
        text = self.manual_hex_var.get().strip()
        try:
            raw = parse_hex(text)
            if len(raw) != 4:
                messagebox.showwarning("Zła długość", "Tu liczmy CRC tylko dla 4 bajtów")
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
            self.log_ui(f"[{ts()}] INFO Heartbeat ON {name} co {ms} ms")
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

    def start_scan_worker(self, start_value: int, end_value: int, window_s: float, delay_ms: int):
        if self.scan_running:
            messagebox.showwarning("Scan aktywny", "Najpierw zatrzymaj obecny autoscan")
            return

        self.scan_running = True
        self.scan_stop_event.clear()

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
                    total += 1
                    try:
                        self.worker.clear_rx_queue()
                        frame = self.worker.send_payload4(payload, f"scan:{hx(payload)}")
                        responses = self.worker.collect_responses(window_s)
                        sign = tuple(hx(r) for r in responses)

                        if baseline is None:
                            baseline = sign

                        if sign != baseline:
                            hits += 1
                            log_append(RESP_LOG_FILE, "=" * 70)
                            log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} CMD {hx(payload)}")
                            log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} TX  {hx(frame)}")
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
                self.scan_stop_event.clear()

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

    def autotest_stop(self):
        self.autotest_running = False
        self.autotest_label.config(text="Zatrzymano")

    def _autotest_show(self):
        if not self.autotest_running or self.autotest_current is None:
            self.autotest_label.config(text="Nie uruchomiono")
            return
        payload = int_to_payload4(self.autotest_current)
        total = (self.autotest_to - self.autotest_from) + 1
        index = (self.autotest_current - self.autotest_from) + 1
        self.autotest_label.config(
            text=f"Krok {index}/{total}: [{hx(payload)}]  zakres: {hx(int_to_payload4(self.autotest_from))} -> {hx(int_to_payload4(self.autotest_to))}"
        )

    def autotest_fire_current(self):
        if not self.autotest_running or self.autotest_current is None:
            return

        payload = int_to_payload4(self.autotest_current)

        def worker():
            try:
                self.worker.clear_rx_queue()
                frame = self.worker.send_payload4(payload, f"autotest:{hx(payload)}")
                responses = self.worker.collect_responses(0.45)

                log_append(RESP_LOG_FILE, "=" * 70)
                log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} AUTOTEST {hx(payload)}")
                log_append(RESP_LOG_FILE, f"{time.strftime('%Y-%m-%d %H:%M:%S')} TX {hx(frame)}")
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


if __name__ == "__main__":
    run_selftest()
    app = App()
    app.mainloop()

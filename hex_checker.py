# -*- coding: utf-8 -*-
"""
Card Verifizier Checker
- Der Scanner liest einen Link (QR-Code); darin steht ein Code wie H98114CK-YEN-6FX
- Das Kartenleser-Programm zeigt denselben Code neben "WTP-Nummer 64 bit:" an
- Dieses Tool vergleicht beide: gruen = Treffer, rot = kein Treffer
- Unter Windows werden Scans GLOBAL empfangen (auch wenn dieses Fenster nicht aktiv ist)
- Alle Scans erscheinen in einer Liste und werden in scan_liste.txt (und hex_log.rtf) gespeichert
Start:  python hex_checker.py
"""
import os
import queue
import re
import sys
import threading
import time
import tkinter as tk
from datetime import datetime

IS_WIN = sys.platform == "win32"
WINDOW_TITLE_DEFAULT = "Card Verifizier"

# Ein Scanner "tippt" sehr schnell. Zeichen mit weniger als MAX_GAP Sekunden
# Abstand gelten als ein Scan, der mit Enter endet.
MAX_GAP = 0.06
MIN_LEN = 10

# ============================================================
# Code-Typen. Fuer neue Codes in der Zukunft nur eine Zeile ergaenzen:
#   (Name, Regex-Muster)
# ============================================================
A = "[A-Za-z0-9]"
NB = "(?<![A-Za-z0-9-])"
NA = "(?![A-Za-z0-9-])"
PATTERNS = [
    ("WTP-64bit", re.compile(NB + A + "{8}-" + A + "{3}-" + A + "{3}" + NA)),
    # Beispiel fuer spaeter:
    # ("Anderer-Code", re.compile(NB + A + "{4}-" + A + "{4}-" + A + "{4}" + NA)),
]

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
LOG_PATH = os.path.join(BASE_DIR, "hex_log.rtf")
TXT_PATH = os.path.join(BASE_DIR, "scan_liste.txt")

SCAN_Q = queue.Queue()

# ---------------- Fenster lesen + globaler Scan-Empfang (nur Windows) ----------------
if IS_WIN:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND,
                                     wintypes.LPARAM)
    WM_GETTEXT = 0x000D
    SMTO_ABORTIFHUNG = 0x0002

    def _text_of(hwnd):
        buf = ctypes.create_unicode_buffer(4096)
        res = wintypes.LPARAM(0)
        ok = user32.SendMessageTimeoutW(
            hwnd, WM_GETTEXT, 4096, ctypes.cast(buf, ctypes.c_void_p),
            SMTO_ABORTIFHUNG, 300, ctypes.byref(res))
        return buf.value if ok else ""

    def find_windows(title_part):
        found = []

        def cb(hwnd, _):
            if user32.IsWindowVisible(hwnd):
                n = user32.GetWindowTextLengthW(hwnd)
                if n:
                    b = ctypes.create_unicode_buffer(n + 1)
                    user32.GetWindowTextW(hwnd, b, n + 1)
                    if title_part.lower() in b.value.lower():
                        found.append(hwnd)
            return True

        user32.EnumWindows(WNDENUMPROC(cb), 0)
        return found

    def read_window_text(title_part):
        texts = []
        for hwnd in find_windows(title_part):
            texts.append(_text_of(hwnd))

            def cb(child, _):
                t = _text_of(child)
                if t:
                    texts.append(t)
                return True

            user32.EnumChildWindows(hwnd, WNDENUMPROC(cb), 0)
            try:  # optional fuer moderne Programme:  pip install pywinauto
                from pywinauto import Desktop
                w = Desktop(backend="uia").window(handle=hwnd)
                for c in w.descendants():
                    t = c.window_text()
                    if t:
                        texts.append(t)
            except Exception:
                pass
        return "\n".join(texts)

    # ---- globaler Tastatur-Hook: empfaengt Scanner-Eingaben immer ----
    _HOOK_REFS = []

    def start_global_hook(q):
        class KBD(ctypes.Structure):
            _fields_ = [("vkCode", wintypes.DWORD),
                        ("scanCode", wintypes.DWORD),
                        ("flags", wintypes.DWORD),
                        ("time", wintypes.DWORD),
                        ("dwExtraInfo", ctypes.c_size_t)]

        HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int,
                                      wintypes.WPARAM, wintypes.LPARAM)
        user32.CallNextHookEx.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                          wintypes.WPARAM, wintypes.LPARAM]
        user32.CallNextHookEx.restype = ctypes.c_ssize_t
        user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC,
                                             ctypes.c_void_p, wintypes.DWORD]
        user32.SetWindowsHookExW.restype = ctypes.c_void_p
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = ctypes.c_void_p
        user32.GetForegroundWindow.restype = wintypes.HWND
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND,
                                                    ctypes.c_void_p]
        user32.GetKeyboardLayout.argtypes = [wintypes.DWORD]
        user32.GetKeyboardLayout.restype = ctypes.c_void_p
        user32.ToUnicodeEx.argtypes = [wintypes.UINT, wintypes.UINT,
                                       ctypes.c_void_p, wintypes.LPWSTR,
                                       ctypes.c_int, wintypes.UINT,
                                       ctypes.c_void_p]
        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG),
                                       wintypes.HWND, wintypes.UINT,
                                       wintypes.UINT]

        st = {"buf": [], "last": 0.0}
        MODS = (0x10, 0xA0, 0xA1, 0x11, 0xA2, 0xA3, 0x12, 0xA4, 0xA5,
                0x14, 0x5B, 0x5C)

        def to_char(vk, sc):
            keys = (ctypes.c_ubyte * 256)()
            for code in (0x10, 0x11, 0x12):
                if user32.GetAsyncKeyState(code) & 0x8000:
                    keys[code] = 0x80
            if user32.GetKeyState(0x14) & 1:
                keys[0x14] = 1
            hwnd = user32.GetForegroundWindow()
            tid = user32.GetWindowThreadProcessId(hwnd, None)
            layout = user32.GetKeyboardLayout(tid)
            buf = ctypes.create_unicode_buffer(8)
            n = user32.ToUnicodeEx(vk, sc, keys, buf, 8, 4, layout)
            return buf.value[:1] if n == 1 else ""

        def proc(n_code, w_param, l_param):
            try:
                if n_code == 0 and w_param in (0x100, 0x104):
                    k = ctypes.cast(l_param, ctypes.POINTER(KBD)).contents
                    now = time.time()
                    if now - st["last"] > MAX_GAP:
                        st["buf"] = []
                    st["last"] = now
                    if k.vkCode == 0x0D:
                        text = "".join(st["buf"])
                        st["buf"] = []
                        if len(text) >= MIN_LEN:
                            q.put(text)
                    elif k.vkCode not in MODS:
                        ch = to_char(k.vkCode, k.scanCode)
                        if ch and ch.isprintable():
                            st["buf"].append(ch)
            except Exception:
                pass
            return user32.CallNextHookEx(None, n_code, w_param, l_param)

        cb = HOOKPROC(proc)
        _HOOK_REFS.append(cb)
        ok = {"v": None}

        def run():
            h = user32.SetWindowsHookExW(
                13, cb, kernel32.GetModuleHandleW(None), 0)
            ok["v"] = bool(h)
            if not h:
                return
            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))

        threading.Thread(target=run, daemon=True).start()
        for _ in range(20):
            if ok["v"] is not None:
                break
            time.sleep(0.05)
        return bool(ok["v"])
else:
    SIMULATED = {"text": ""}

    def read_window_text(title_part):  # Testmodus am Mac
        return SIMULATED["text"]

    def start_global_hook(q):
        return False


def find_codes(text):
    """{Typ: Code} fuer jedes Muster, das im Text gefunden wird."""
    out = {}
    for name, rx in PATTERNS:
        m = rx.search(text or "")
        if m:
            out[name] = m.group(0)
    return out


# ---------------- Protokoll: RTF (farbig) + TXT (Liste) ----------------
def _esc(s):
    out = []
    for ch in s:
        o = ord(ch)
        if ch in "\\{}":
            out.append("\\" + ch)
        elif o > 127:
            out.append("\\u%d?" % (o if o < 32768 else o - 65536))
        else:
            out.append(ch)
    return "".join(out)


RTF_HEADER = ("{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Consolas;}}"
              "{\\colortbl;\\red0\\green150\\blue0;\\red210\\green0\\blue0;}"
              "\\f0\\fs20\n")


def write_log(ts, ok, scanned, screen, note=""):
    color, status = (1, "PASS") if ok else (2, "FAIL")
    line = "%s | \\cf%d\\b %s\\b0\\cf0  | scan=%s | screen=%s %s\\line\n" % (
        ts, color, status, _esc(scanned or "-"), _esc(screen or "-"),
        _esc(note))
    if not os.path.exists(LOG_PATH):
        with open(LOG_PATH, "wb") as f:
            f.write((RTF_HEADER + "}").encode("ascii"))
    with open(LOG_PATH, "r+b") as f:
        data = f.read()
        pos = data.rfind(b"}")
        f.seek(pos)
        f.write(line.encode("ascii") + b"}")
        f.truncate()


def write_txt(ts, ok, scanned, screen, note=""):
    with open(TXT_PATH, "a", encoding="utf-8") as f:
        f.write("%s\t%s\tScan=%s\tBildschirm=%s\t%s\n" % (
            ts, "OK" if ok else "FEHLER", scanned or "-", screen or "-", note))


# ---------------- Oberflaeche ----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Card Verifizier Checker")
        self.geometry("720x720")
        self.configure(bg="#2b2b2b")
        self.screen_codes = {}
        self.count_ok = 0
        self.count_bad = 0

        f = tk.Frame(self, bg="#2b2b2b")
        f.pack(fill="x", padx=12, pady=8)
        tk.Label(f, text="Teil des Fenstertitels des Programms:", fg="white",
                 bg="#2b2b2b").pack(anchor="w")
        self.title_var = tk.StringVar(value=WINDOW_TITLE_DEFAULT)
        tk.Entry(f, textvariable=self.title_var,
                 font=("Segoe UI", 12)).pack(fill="x")

        if not IS_WIN:
            tk.Label(f, text="[Mac-Testmodus] Simulierter Fenstertext:",
                     fg="#ffcc00", bg="#2b2b2b").pack(anchor="w", pady=(8, 0))
            self.sim_var = tk.StringVar()
            tk.Entry(f, textvariable=self.sim_var,
                     font=("Consolas", 12)).pack(fill="x")
            self.sim_var.trace_add(
                "write", lambda *a: SIMULATED.update(text=self.sim_var.get()))

        row = tk.Frame(f, bg="#2b2b2b")
        row.pack(fill="x", pady=4)
        tk.Button(row, text="Aktualisieren",
                  command=self.refresh).pack(side="left")
        tk.Button(row, text="Gelesenen Text anzeigen",
                  command=self.debug).pack(side="left", padx=6)
        self.live = tk.BooleanVar(value=True)
        self.case = tk.BooleanVar(value=False)
        self.top = tk.BooleanVar(value=True)
        for txt, var, cmd in (
                ("Live", self.live, None),
                ("Groß-/Kleinschreibung beachten", self.case, None),
                ("Immer im Vordergrund", self.top, self.set_top)):
            tk.Checkbutton(row, text=txt, variable=var, command=cmd,
                           fg="white", bg="#2b2b2b", selectcolor="#444",
                           activebackground="#2b2b2b").pack(side="left", padx=6)
        self.set_top()

        self.hook_ok = IS_WIN and start_global_hook(SCAN_Q)
        if self.hook_ok:
            msg, col = "Scan-Empfang: GLOBAL aktiv (auch im Hintergrund)", "#7CFC8A"
        elif IS_WIN:
            msg, col = "Scan-Empfang: Hook fehlgeschlagen - nur Eingabefeld", "#ffcc00"
        else:
            msg, col = "Scan-Empfang: nur Eingabefeld (Mac-Test)", "#ffcc00"
        tk.Label(self, text=msg, fg=col, bg="#2b2b2b").pack()

        self.exp_lbl = tk.Label(self, text="Code auf dem Bildschirm: ---",
                                fg="white", bg="#2b2b2b",
                                font=("Consolas", 16))
        self.exp_lbl.pack(pady=4)

        tk.Label(self, text="Manuelle Eingabe / Test (Enter):", fg="#bbb",
                 bg="#2b2b2b").pack()
        self.scan_var = tk.StringVar()
        self.scan = tk.Entry(self, textvariable=self.scan_var,
                             font=("Consolas", 12), justify="center")
        self.scan.pack(fill="x", padx=12)
        self.scan.bind("<Return>", self.on_manual)

        self.banner = tk.Label(self, text="Warte auf Scan...", fg="white",
                               bg="#555", font=("Segoe UI", 26, "bold"),
                               height=2)
        self.banner.pack(fill="x", padx=12, pady=10)

        self.stats = tk.Label(self, text="OK: 0   Fehler: 0", fg="white",
                              bg="#2b2b2b", font=("Segoe UI", 11, "bold"))
        self.stats.pack()

        lf = tk.Frame(self, bg="#2b2b2b")
        lf.pack(fill="both", expand=True, padx=12, pady=8)
        sb = tk.Scrollbar(lf)
        sb.pack(side="right", fill="y")
        self.listbox = tk.Text(lf, height=10, bg="#1e1e1e", fg="white",
                               font=("Consolas", 10), state="disabled",
                               yscrollcommand=sb.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        sb.config(command=self.listbox.yview)
        self.listbox.tag_config("ok", foreground="#4cd964")
        self.listbox.tag_config("bad", foreground="#ff5252")

        self.after(500, self.tick)
        self.after(100, self.poll)

    def set_top(self):
        self.attributes("-topmost", bool(self.top.get()))

    def refresh(self):
        txt = read_window_text(self.title_var.get().strip())
        self.screen_codes = find_codes(txt)
        shown = ", ".join(self.screen_codes.values()) or "nicht gefunden"
        self.exp_lbl.config(text="Code auf dem Bildschirm: %s" % shown)

    def tick(self):
        if self.live.get():
            self.refresh()
        self.after(500, self.tick)

    def poll(self):
        try:
            while True:
                self.process(SCAN_Q.get_nowait())
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def debug(self):
        w = tk.Toplevel(self)
        w.title("Aus dem Fenster gelesener Text")
        t = tk.Text(w, width=70, height=20)
        t.pack(fill="both", expand=True)
        t.insert("1.0", read_window_text(self.title_var.get().strip())
                 or "(Nichts gelesen - Fenstertitel prüfen)")

    def show(self, ok, msg):
        c = "#1e9e3a" if ok else "#c62828"
        self.configure(bg=c)
        self.banner.config(text=msg, bg=c)
        if not ok:
            self.bell()

    def same(self, a, b):
        return a == b if self.case.get() else a.lower() == b.lower()

    def add_row(self, ts, ok, scanned, screen, note):
        if ok:
            self.count_ok += 1
        else:
            self.count_bad += 1
        self.stats.config(text="OK: %d   Fehler: %d" % (self.count_ok,
                                                         self.count_bad))
        line = "%s  %-6s %s  |  %s %s\n" % (
            ts[11:], "OK" if ok else "FEHLER", scanned or "-",
            screen or "-", note)
        self.listbox.config(state="normal")
        self.listbox.insert("end", line, "ok" if ok else "bad")
        self.listbox.see("end")
        self.listbox.config(state="disabled")

    def on_manual(self, _e=None):
        link = self.scan_var.get().strip()
        self.scan_var.set("")
        if link:
            self.process(link)

    def process(self, link):
        """Ein gescannter Link: mit dem Code im Programmfenster vergleichen."""
        self.refresh()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        scanned = find_codes(link)
        if not scanned:
            ok, code, screen, note = False, link[:60], None, "(kein Code im Link)"
            self.show(False, "✖ Kein Code im Link gefunden")
        else:
            name, code = next(iter(scanned.items()))
            screen = self.screen_codes.get(name)
            if not screen:
                ok, note = False, "(kein Code im Fenster)"
                self.show(False, "✖ Kein Code im Fenster gefunden")
            elif self.same(code, screen):
                ok, note = True, ""
                self.show(True, "✔ Übereinstimmung")
            else:
                ok, note = False, "(keine Übereinstimmung)"
                self.show(False, "✖ KEINE Übereinstimmung!")
        try:
            write_log(ts, ok, code, screen, note)
            write_txt(ts, ok, code, screen, note)
        except Exception:
            pass
        self.add_row(ts, ok, code, screen, note)


if __name__ == "__main__":
    App().mainloop()

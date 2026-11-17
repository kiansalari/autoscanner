# -*- coding: utf-8 -*-
"""
Card Verifizier Checker
- اسکنر یک لینک می‌خواند؛ داخل لینک (هر جا) کدی مثل H98114CK-YEN-6FX هست
- برنامه‌ی کارت‌خوان در ویندوز همین کد را کنار «WTP-Nummer 64 bit:» نشان می‌دهد
- این ابزار دو کد را مقایسه می‌کند: سبز = تطابق، قرمز = عدم تطابق
روی مک هم اجرا می‌شود (حالت تست)، روی ویندوز پنجره‌ی واقعی را می‌خواند.
اجرا:  python hex_checker.py
"""
import os
import re
import sys
import tkinter as tk
from datetime import datetime

IS_WIN = sys.platform == "win32"
WINDOW_TITLE_DEFAULT = "Card Verifizier"

# ============================================================
# انواع کد. برای پشتیبانی از کد جدید در آینده فقط یک خط اضافه کنید:
#   (نام, الگوی regex)
# ============================================================
A = "[A-Za-z0-9]"
NB = "(?<![A-Za-z0-9-])"   # قبلش حرف/عدد/خط‌تیره نباشد
NA = "(?![A-Za-z0-9-])"    # بعدش هم نباشد
PATTERNS = [
    ("WTP-64bit", re.compile(NB + A + "{8}-" + A + "{3}-" + A + "{3}" + NA)),
    # مثال برای آینده:
    # ("کد-دیگر", re.compile(NB + A + "{4}-" + A + "{4}-" + A + "{4}" + NA)),
]

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])),
                        "hex_log.rtf")

# ---------------- خواندن پنجره (فقط ویندوز) ----------------
if IS_WIN:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
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
            try:  # اختیاری برای برنامه‌های مدرن:  pip install pywinauto
                from pywinauto import Desktop
                w = Desktop(backend="uia").window(handle=hwnd)
                for c in w.descendants():
                    t = c.window_text()
                    if t:
                        texts.append(t)
            except Exception:
                pass
        return "\n".join(texts)
else:
    SIMULATED = {"text": ""}

    def read_window_text(title_part):  # حالت تست روی مک
        return SIMULATED["text"]


def find_codes(text):
    """{نام نوع: کد} برای هر الگویی که در متن پیدا شود."""
    out = {}
    for name, rx in PATTERNS:
        m = rx.search(text or "")
        if m:
            out[name] = m.group(0)
    return out


# ---------------- لاگ RTF ----------------
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


def write_log(ok, scanned, screen, note=""):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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


# ---------------- رابط کاربری ----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Card Verifizier Checker")
        self.geometry("680x540")
        self.configure(bg="#2b2b2b")
        self.screen_codes = {}

        f = tk.Frame(self, bg="#2b2b2b")
        f.pack(fill="x", padx=12, pady=8)
        tk.Label(f, text="Teil des Fenstertitels des Programms:", fg="white",
                 bg="#2b2b2b").pack(anchor="e")
        self.title_var = tk.StringVar(value=WINDOW_TITLE_DEFAULT)
        tk.Entry(f, textvariable=self.title_var,
                 font=("Segoe UI", 12)).pack(fill="x")

        if not IS_WIN:
            tk.Label(f, text="[Mac-Testmodus] Simulierter Fenstertext:",
                     fg="#ffcc00", bg="#2b2b2b").pack(anchor="e", pady=(8, 0))
            self.sim_var = tk.StringVar()
            tk.Entry(f, textvariable=self.sim_var,
                     font=("Consolas", 12)).pack(fill="x")
            self.sim_var.trace_add(
                "write", lambda *a: SIMULATED.update(text=self.sim_var.get()))

        row = tk.Frame(f, bg="#2b2b2b")
        row.pack(fill="x", pady=4)
        tk.Button(row, text="Aktualisieren", command=self.refresh).pack(side="left")
        tk.Button(row, text="Gelesenen Text anzeigen",
                  command=self.debug).pack(side="left", padx=6)
        self.live = tk.BooleanVar(value=True)
        tk.Checkbutton(row, text="Live", variable=self.live, fg="white",
                       bg="#2b2b2b", selectcolor="#444",
                       activebackground="#2b2b2b").pack(side="left", padx=6)
        self.case = tk.BooleanVar(value=False)
        tk.Checkbutton(row, text="Groß-/Kleinschreibung beachten", variable=self.case,
                       fg="white", bg="#2b2b2b", selectcolor="#444",
                       activebackground="#2b2b2b").pack(side="left", padx=6)

        self.exp_lbl = tk.Label(self, text="Code auf dem Bildschirm: ---", fg="white",
                                bg="#2b2b2b", font=("Consolas", 16))
        self.exp_lbl.pack(pady=6)

        tk.Label(self, text="Gescannter Link (Scanner sendet Enter):", fg="white",
                 bg="#2b2b2b").pack()
        self.scan_var = tk.StringVar()
        self.scan = tk.Entry(self, textvariable=self.scan_var,
                             font=("Consolas", 14), justify="center")
        self.scan.pack(fill="x", padx=12)
        self.scan.bind("<Return>", self.on_scan)
        self.scan.focus_set()

        self.banner = tk.Label(self, text="Warte auf Scan...", fg="white",
                               bg="#555", font=("Segoe UI", 28, "bold"))
        self.banner.pack(fill="both", expand=True, padx=12, pady=12)
        self.after(500, self.tick)

    def refresh(self):
        txt = read_window_text(self.title_var.get().strip())
        self.screen_codes = find_codes(txt)
        shown = ", ".join(self.screen_codes.values()) or "nicht gefunden"
        self.exp_lbl.config(text="Code auf dem Bildschirm: %s" % shown)

    def tick(self):
        if self.live.get():
            self.refresh()
        self.after(500, self.tick)

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

    def on_scan(self, _e=None):
        link = self.scan_var.get().strip()
        self.scan_var.set("")
        if not link:
            return
        self.refresh()
        scanned = find_codes(link)
        if not scanned:
            self.show(False, "✖ Kein Code im Link gefunden")
            write_log(False, link[:60], None, "(no code in link)")
        else:
            name, code = next(iter(scanned.items()))
            screen = self.screen_codes.get(name)
            if not screen:
                self.show(False, "✖ Kein Code im Fenster gefunden")
                write_log(False, code, None, "(no code on screen)")
            elif self.same(code, screen):
                self.show(True, "✔ Übereinstimmung")
                write_log(True, code, screen)
            else:
                self.show(False, "✖ KEINE Übereinstimmung!")
                write_log(False, code, screen, "(mismatch)")
        self.scan.focus_set()


if __name__ == "__main__":
    App().mainloop()

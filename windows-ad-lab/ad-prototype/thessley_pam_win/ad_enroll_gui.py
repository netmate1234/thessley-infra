"""Small GUI for self-enrolling the currently signed-in AD account's phone."""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from . import ad_agent, ad_cli, qr


class EnrollmentWindow:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Thessley · Add phone for Windows sign-in")
        self.root.geometry("600x600")
        self.root.minsize(500, 560)
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.cancel = threading.Event()
        self.confirm = threading.Event()
        self.request_id: str | None = None
        self.worker: threading.Thread | None = None
        self.closed = False

        account = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}".strip("\\")
        ttk.Label(root, text="Add a phone for Windows sign-in", font=("Segoe UI", 16, "bold")).pack(pady=(8, 1))
        ttk.Label(root, text=f"Signed-in account: {account}", font=("Segoe UI", 10)).pack(pady=(0, 3))
        ttk.Label(
            root,
            text="Start enrollment here, then scan this window with Thessley Passkey.\n"
                 "The phone key is linked only after you confirm matching codes.",
            justify="center", wraplength=540,
        ).pack(pady=(0, 4))

        self.qr_canvas = tk.Canvas(root, width=280, height=280, background="white", highlightthickness=1,
                                   highlightbackground="#888")
        self.qr_canvas.pack(pady=3)
        self.qr_canvas.create_text(140, 140, text="QR code appears here", fill="#555", font=("Segoe UI", 10))

        link_row = ttk.Frame(root)
        link_row.pack(fill="x", padx=14, pady=(3, 4))
        self.link = tk.Entry(link_row, state="readonly", readonlybackground="white")
        self.link.pack(side="left", fill="x", expand=True)
        self.copy_button = ttk.Button(link_row, text="Copy link", command=self.copy_link, state="disabled")
        self.copy_button.pack(side="left", padx=(8, 0))

        self.code_label = ttk.Label(root, text="", font=("Segoe UI", 20, "bold"))
        self.code_label.pack(pady=(0, 1))
        self.status = ttk.Label(root, text="Ready. Start to request a fresh enrollment QR.",
                                wraplength=600, justify="center")
        self.status.pack(fill="x", padx=14, pady=3)

        actions = ttk.Frame(root)
        actions.pack(pady=(3, 5))
        self.start_button = ttk.Button(actions, text="Start enrollment", command=self.start)
        self.start_button.pack(side="left", padx=6)
        self.confirm_button = ttk.Button(actions, text="Codes match — finish", command=self.confirm_match,
                                         state="disabled")
        self.confirm_button.pack(side="left", padx=6)
        self.cancel_button = ttk.Button(actions, text="Cancel", command=self.cancel_enrollment, state="disabled")
        self.cancel_button.pack(side="left", padx=6)

        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(150, self.drain_events)

    def start(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        self.cancel.clear()
        self.confirm.clear()
        self.request_id = None
        self.link.configure(state="normal")
        self.link.delete(0, "end")
        self.link.configure(state="readonly")
        self.copy_button.configure(state="disabled")
        self.code_label.configure(text="")
        self.confirm_button.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.status.configure(text="Checking the signed-in domain account and starting enrollment…")
        self.worker = threading.Thread(target=self.enroll, daemon=True)
        self.worker.start()

    def enroll(self) -> None:
        try:
            ad_cli._require_domain_joined()
            sid = ad_cli._current_user_sid()
            started = ad_agent.start_phone_enrollment(sid)
            self.request_id = started["request_id"]
            rows = qr.bitmap_rows(started["link"], border=2)
            if not rows:
                raise RuntimeError("The QR generator is unavailable. Use the displayed link instead.")
            self.events.put(("started", (started["link"], rows, started["authority"], started["username"])))

            while not self.cancel.is_set():
                state = ad_agent.phone_enrollment_status(started["request_id"])
                if state["status"] == "ready":
                    self.events.put(("pairing", state["pairing_code"]))
                    while not self.cancel.is_set() and not self.confirm.wait(0.2):
                        pass
                    if self.cancel.is_set():
                        ad_agent.cancel_phone_enrollment(started["request_id"])
                        self.events.put(("cancelled", None))
                        return
                    ad_agent.confirm_phone_enrollment(started["request_id"], state["pairing_code"])
                    self.events.put(("complete", None))
                    return
                if state["status"] in ("expired", "denied"):
                    self.events.put(("expired", state["status"]))
                    return
                self.events.put(("waiting", None))
                self.cancel.wait(1.0)
            ad_agent.cancel_phone_enrollment(started["request_id"])
            self.events.put(("cancelled", None))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def draw_qr(self, rows: list[str]) -> None:
        self.qr_canvas.delete("all")
        width = max(len(row) for row in rows)
        height = len(rows)
        unit = max(1, min(5, 260 // max(width, height)))
        size_x, size_y = width * unit, height * unit
        left, top = (280 - size_x) // 2, (280 - size_y) // 2
        self.qr_canvas.create_rectangle(left, top, left + size_x, top + size_y, fill="white", outline="")
        for y, row in enumerate(rows):
            for x, pixel in enumerate(row):
                if pixel == "1":
                    x0, y0 = left + x * unit, top + y * unit
                    self.qr_canvas.create_rectangle(x0, y0, x0 + unit, y0 + unit, fill="black", outline="")

    def drain_events(self) -> None:
        try:
            while True:
                name, value = self.events.get_nowait()
                if name == "started":
                    link, rows, authority, username = value  # type: ignore[misc]
                    self.draw_qr(rows)
                    self.link.configure(state="normal")
                    self.link.insert(0, link)
                    self.link.configure(state="readonly")
                    self.copy_button.configure(state="normal")
                    self.status.configure(text=f"Scan for {authority}\\{username} with Thessley Passkey, then approve Add phone.")
                elif name == "waiting":
                    self.status.configure(text="Waiting for the phone to approve enrollment…")
                elif name == "pairing":
                    self.code_label.configure(text=str(value))
                    self.confirm_button.configure(state="normal")
                    self.status.configure(text="Compare this code with the phone. Confirm only if they match.")
                elif name == "complete":
                    self.status.configure(text="Phone enrolled for this domain account and computer.")
                    self.finish()
                    messagebox.showinfo("Enrollment complete", "The phone is enrolled for this Windows domain account.")
                elif name == "cancelled":
                    self.status.configure(text="Enrollment cancelled. No phone key was activated.")
                    self.finish()
                elif name == "expired":
                    self.status.configure(text="The request expired or was cancelled. Start a fresh enrollment.")
                    self.finish()
                elif name == "error":
                    self.status.configure(text=f"Could not complete enrollment: {value}")
                    self.finish()
        except queue.Empty:
            pass
        if not self.closed:
            self.root.after(150, self.drain_events)

    def finish(self) -> None:
        self.start_button.configure(state="normal")
        self.confirm_button.configure(state="disabled")
        self.cancel_button.configure(state="disabled")

    def copy_link(self) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(self.link.get())
        self.status.configure(text="Enrollment link copied. It expires when the request ends.")

    def confirm_match(self) -> None:
        if messagebox.askyesno("Confirm pairing", "Do the phone and this PC show the same pairing code?"):
            self.confirm.set()
            self.confirm_button.configure(state="disabled")
            self.status.configure(text="Confirming the matching code…")

    def cancel_enrollment(self) -> None:
        self.cancel.set()
        self.confirm.set()
        self.cancel_button.configure(state="disabled")
        self.confirm_button.configure(state="disabled")
        self.status.configure(text="Cancelling enrollment…")

    def close(self) -> None:
        if self.worker and self.worker.is_alive():
            self.cancel_enrollment()
            self.closed = True
            self.root.after(250, self.root.destroy)
        else:
            self.root.destroy()


def main() -> int:
    root = tk.Tk()
    EnrollmentWindow(root)
    root.mainloop()
    return 0

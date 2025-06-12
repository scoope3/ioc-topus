"""
ioc_topus.gui.widgets
~~~~~~~~~~~~~~~~~~~~~
Reusable Tkinter widgets:
    • ToolTip            – basic hover tooltip
    • SmoothScrolledFrame – canvas-based scrollable frame
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk     # ttk not used yet but helpful for future widgets


# ---------------------------------------------------------------------------#
# 1)  Tooltip
# ---------------------------------------------------------------------------#
class ToolTip:
    """
    A basic tooltip that appears when hovering over *widget*.
    """

    def __init__(self, widget: tk.Widget, text: str = "widget info") -> None:
        self.widget = widget
        self.text = text
        self.waittime = 500           # ms before showing
        self.wraplength = 180         # px
        self.id: str | None = None
        self.tw: tk.Toplevel | None = None

        widget.bind("<Enter>", self._on_enter)
        widget.bind("<Leave>", self._on_leave)
        widget.bind("<ButtonPress>", self._on_leave)

    # ---------------- internal callbacks ----------------------------------
    def _on_enter(self, _event=None) -> None:
        self._schedule()

    def _on_leave(self, _event=None) -> None:
        self._unschedule()
        self._hide_tooltip()

    # ---------------- scheduling helpers ----------------------------------
    def _schedule(self) -> None:
        self._unschedule()
        self.id = self.widget.after(self.waittime, self._show_tooltip)

    def _unschedule(self) -> None:
        if self.id is not None:
            self.widget.after_cancel(self.id)
            self.id = None

    # ---------------- creation / destroy ----------------------------------
    def _show_tooltip(self) -> None:
        if self.tw:                       # already showing
            return
        x, y, *_ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20

        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)     # no border or title bar
        self.tw.wm_geometry(f"+{x}+{y}")

        label = tk.Label(
            self.tw,
            text=self.text,
            justify="left",
            background="#ffffe0",
            relief="solid",
            borderwidth=1,
            wraplength=self.wraplength,
            font=("Segoe UI", 10, "normal"),
        )
        label.pack(ipadx=1, ipady=1)

    def _hide_tooltip(self) -> None:
        if self.tw is not None:
            self.tw.destroy()
            self.tw = None


# ---------------------------------------------------------------------------#
# 2)  Scrollable frame
# ---------------------------------------------------------------------------#
class SmoothScrolledFrame(tk.Frame):
    """
    A canvas-based frame with a vertical scrollbar.
    Call `.get_inner_frame()` to pack/place your widgets.
    """

    def __init__(self, parent, *, bg_color: str = "#F0F0F0", **kwargs):
        super().__init__(parent, bg=bg_color, **kwargs)

        self.canvas = tk.Canvas(self, bg=bg_color, highlightthickness=0)
        self.inner_frame = tk.Frame(self.canvas, bg=bg_color)

        self.v_scroll = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.v_scroll.set)

        self.v_scroll.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas_window = self.canvas.create_window((0, 0), window=self.inner_frame, anchor="nw")

        # resize & scroll bindings
        self.inner_frame.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self.inner_frame.bind("<Enter>", self._bind_mousewheel)
        self.inner_frame.bind("<Leave>", self._unbind_mousewheel)

    # ------------- auto-size & scroll logic -------------------------------
    def _on_frame_configure(self, _event=None) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event) -> None:
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    # ------------- mouse-wheel helpers -----------------------------------
    def _bind_mousewheel(self, _event=None) -> None:
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)   # Linux
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)

    def _unbind_mousewheel(self, _event=None) -> None:
        self.canvas.unbind_all("<MouseWheel>")
        self.canvas.unbind_all("<Button-4>")
        self.canvas.unbind_all("<Button-5>")

    def _on_mousewheel(self, event) -> None:
        if event.delta:                        # Windows / macOS
            self.canvas.yview_scroll(int(-event.delta / 120), "units")
        elif event.num == 4:                   # Linux scroll-up
            self.canvas.yview_scroll(-1, "units")
        elif event.num == 5:                   # Linux scroll-down
            self.canvas.yview_scroll(1, "units")

    # ---------------------------------------------------------------------
    def get_inner_frame(self) -> tk.Frame:
        """Return the frame you can pack/place widgets onto."""
        return self.inner_frame


# ---------------------------------------------------------------------------#
# 3)  Explicit public surface
# ---------------------------------------------------------------------------#
__all__ = ["ToolTip", "SmoothScrolledFrame"]

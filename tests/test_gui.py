# tests/test_gui.py
import pytest
import tkinter as tk
from ioc_topus.gui.app import open_gui

@pytest.mark.gui
def test_window_launches_and_closes():
    root = open_gui(test_mode=True)
    assert isinstance(root, tk.Tk)
    assert root.title() == "IOC-Topus"
    root.destroy()

"""
ioc_topus package root
~~~~~~~~~~~~~~~~~~~~~~

* Exposes a convenience ``open_gui()`` wrapper.
* Publishes ``__version__`` (pulled from installed metadata).

Nothing heavy (Tkinter windows, API clients, etc.) runs at import time.
"""

from __future__ import annotations

from importlib.metadata import version as _pkg_version

__version__: str = _pkg_version("ioc_topus")


# ---------------------------------------------------------------------------#
# Lazy GUI launcher
# ---------------------------------------------------------------------------#
def open_gui(**kwargs):
    """
    Launch the IOCTopus Tkinter application.

    Parameters
    ----------
    **kwargs
        Passed straight through to :pyfunc:`ioc_topus.gui.app.open_gui`.

    Notes
    -----
    Importing Tkinter inside this function (instead of at module import
    time) prevents unit-test discovery from failing in head-less
    environments and keeps package imports lightweight.
    """
    from .gui.app import open_gui as _real_open_gui

    return _real_open_gui(**kwargs)


__all__ = ["open_gui", "__version__"]

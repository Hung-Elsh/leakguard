"""Run slow work (checks) off the window's thread, reporting progress through Qt signals.

Each job opens its own database connection inside its thread (sqlite connections are per thread).
"""

from __future__ import annotations

import threading
import traceback
from typing import Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

from ..models import redact


class JobSignals(QObject):
    progress = Signal(int, int, str, str, str)      # done, total, source, identity, status
    done = Signal(object)                           # the job's result
    failed = Signal(str)                            # full detail (secrets removed), for "Details"


class Job(QRunnable):
    """fn(progress, cancel) -> result. Signals are delivered on the window's thread."""

    def __init__(self, fn: Callable, secrets: list[str] | None = None):
        super().__init__()
        self.fn = fn
        self.secrets = secrets or []
        self.cancel = threading.Event()
        self.signals = JobSignals()
        self.setAutoDelete(False)                   # the window keeps it until it reports back

    def run(self) -> None:
        try:
            result = self.fn(self.signals.progress.emit, self.cancel)
        except Exception:                           # any failure becomes a plain message + saved detail
            self.signals.failed.emit(redact(traceback.format_exc(), self.secrets))
        else:
            self.signals.done.emit(result)


def start(job: Job) -> None:
    QThreadPool.globalInstance().start(job)

"""A page that arrives in a later update (G2-G4): says so in plain words."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QVBoxLayout, QWidget

from ...wording import SOON
from ..widgets.cards import label


class SoonPage(QWidget):
    def __init__(self, title: str):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 24)
        lay.addWidget(label(title, "hero"))
        lay.addWidget(label(SOON, "muted"))
        lay.addStretch(1)
        lay.setAlignment(Qt.AlignmentFlag.AlignTop)

    def refresh(self, _overview) -> None:
        pass

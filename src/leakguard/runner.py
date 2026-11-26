"""Run an external OSINT tool, or (lab profile) read its recorded output from lab/fixtures."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from .config import Settings
from .paths import DATA
from .scope import ScopeGuard


class ToolError(Exception):
    pass


def find_binary(*candidates: str) -> str:
    for c in candidates:
        if "/" in c:
            p = Path(os.path.expanduser(c))
            if p.exists():
                return str(p)
        elif found := shutil.which(c):
            return found
    raise ToolError(f"not installed: {candidates[0]} (run `leakguard doctor`)")


def fixture_path(settings: Settings, tool: str, value: str, ext: str) -> Path:
    assert settings.fixtures_dir
    return settings.fixtures_dir / tool / f"{value}.{ext}"


def tool_output(
    settings: Settings,
    guard: ScopeGuard,
    tool: str,
    value: str,
    ext: str,
    produce: Callable[[Path], Path | None],
) -> str | None:
    """Return the tool's raw output text.

    lab:      read lab/fixtures/<tool>/<value>.<ext>; no fixture means "nothing found".
    internet: produce(workdir) runs the tool and returns the output file; the text is also
              kept under data/raw/ for later review.
    """
    if settings.tools_mode == "fixtures":
        p = fixture_path(settings, tool, value, ext)
        return p.read_text() if p.exists() else None

    guard.check_tool(tool)
    with tempfile.TemporaryDirectory(prefix=f"lg-{tool}-") as tmp:
        out = produce(Path(tmp))
        if out is None or not out.exists():
            return None
        text = out.read_text(errors="replace")
    raw = DATA / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / f"{tool}-{value}.{ext}").write_text(text)
    return text


def run(cmd: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                              env={**os.environ, "NO_COLOR": "1"})
    except subprocess.TimeoutExpired as e:
        raise ToolError(f"{Path(cmd[0]).name} timed out after {timeout}s") from e

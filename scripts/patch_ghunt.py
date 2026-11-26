"""Patch GHunt 2.3.4 for Google API changes (Nov 2026). Safe to run more than once.

1. parsers/people.py: Google replies sometimes omit metadata "container" -> KeyError.
   Fall back to "PROFILE", GHunt's default container.
2. helpers/gmaps.py: the Maps stats endpoint no longer returns JSON -> JSONDecodeError.
   Skip the Maps step instead of crashing, so Calendar and the rest still run.

Usage: python3 scripts/patch_ghunt.py [path-to-ghunt-package]
Re-run after any `pipx upgrade ghunt` / reinstall. Each file gets a .bak copy the first time.
"""
import re
import shutil
import sys
from pathlib import Path

DEFAULT = Path.home() / ".local/share/pipx/venvs/ghunt/lib/python3.12/site-packages/ghunt"


def read(path: Path) -> tuple[str, str]:
    src = path.read_bytes().decode()
    return src, ("\r\n" if "\r\n" in src else "\n")


def write(path: Path, src: str) -> None:
    bak = path.with_suffix(path.suffix + ".bak")
    if not bak.exists():
        shutil.copy2(path, bak)
    path.write_bytes(src.encode())


def patch_people(pkg: Path) -> str:
    path = pkg / "parsers/people.py"
    src, _ = read(path)
    new = src.replace('["metadata"]["container"]', '["metadata"].get("container", "PROFILE")')
    new = re.sub(r'source_ids_data\["container"\]', 'source_ids_data.get("container", "PROFILE")', new)
    if new == src:
        return f"people.py: nothing to change (already patched?)"
    write(path, new)
    return "people.py: patched"


def patch_gmaps(pkg: Path) -> str:
    path = pkg / "helpers/gmaps.py"
    src, nl = read(path)
    old = "    data = json.loads(req.text[5:])" + nl + "    if not data[16][8]:"
    new = nl.join([
        "    try:",
        "        data = json.loads(req.text[5:])",
        "        data[16][8]",
        "    except (ValueError, IndexError, TypeError):",
        '        print(f"[-] Maps endpoint returned an unreadable reply (HTTP {req.status_code}), skipping Maps.")',
        '        return "empty", stats',
        "    if not data[16][8]:",
    ])
    if new in src:
        return "gmaps.py: already patched"
    if src.count(old) != 1:
        return "gmaps.py: expected code not found, NOT changed (GHunt version differs?)"
    write(path, src.replace(old, new))
    return "gmaps.py: patched"


def main() -> None:
    pkg = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    if not (pkg / "parsers/people.py").exists():
        sys.exit(f"GHunt package not found at {pkg}")
    for fn in (patch_people, patch_gmaps):
        print(fn(pkg))


if __name__ == "__main__":
    main()

"""
attack_lib.py -- LAB-ONLY, BENIGN attack simulations.
=====================================================
IMPORTANT: these are NOT weaponised exploits. Each function reproduces the *observable
filesystem effect* that a given web attack would leave in the protected web root -- an
unexpected file appearing, an existing page being altered, a file being deleted -- which
is exactly what the Wazuh FIM gate reacts to. Reproducing the observable (not a working
remote-access payload) is deliberate: it is safer, fully reproducible, and exercises the
detect->heal loop identically. The dropped "shell" is an inert marker with no callback,
no command execution, and no network capability.

Every function returns the wall-clock time the artefact was injected, which is the
`t_attack` the metrics module uses to compute MTTD.

These run ONLY against the isolated lab web root (runtime/webroot). Do not point them
at anything else.
"""
from __future__ import annotations

import time
from pathlib import Path

# An inert marker. A real webshell would contain code; this contains a comment only,
# so it triggers FIM (a new .php file in the web root) without being executable malware.
_INERT_MARKER = (
    "<?php /* ARGUS-LAB BENIGN MARKER -- no functionality, "
    "stands in for a webshell to trigger FIM only */ ?>\n"
)


def simulate_webshell_upload(webroot: str | Path,
                             name: str = "uploads_shell.php") -> float:
    """Observable of a webshell upload: a new, unexpected .php file in the web root."""
    root = Path(webroot)
    t = time.time()
    (root / name).write_text(_INERT_MARKER, encoding="utf-8")
    return t


def simulate_defacement(webroot: str | Path,
                        page: str = "index.php") -> float:
    """Observable of a defacement: an existing page's contents replaced."""
    root = Path(webroot)
    target = root / page
    t = time.time()
    target.write_text("<html><body><h1>ARGUS-LAB defacement marker</h1></body></html>",
                      encoding="utf-8")
    return t


def simulate_file_drop(webroot: str | Path,
                       name: str = "config.bak.php") -> float:
    """Observable of a dropper/persistence artefact: a new file in a plausible location."""
    root = Path(webroot)
    t = time.time()
    (root / name).write_text(_INERT_MARKER, encoding="utf-8")
    return t


def simulate_tamper_delete(webroot: str | Path,
                           page: str = "robots.txt") -> float:
    """Observable of anti-forensic tampering: deletion of an existing file."""
    root = Path(webroot)
    target = root / page
    t = time.time()
    if target.exists():
        target.unlink()
    return t


SCENARIOS = {
    "webshell": simulate_webshell_upload,
    "deface": simulate_defacement,
    "drop": simulate_file_drop,
    "delete": simulate_tamper_delete,
}

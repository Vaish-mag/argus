"""
sensors.py
==========
Turns raw host observations into the 9-feature behaviour Window the anomaly detector
consumes. On a real deployment the controller calls `HostSensor.window()` each tick.

Feature sources (all laptop-cheap):
  * req_per_min, unique_paths, rate_4xx, rate_5xx  <- tail of the DVWA/nginx access log
  * file_change_events                              <- count of recent Wazuh syscheck alerts
  * new_process_events                              <- count of recent Wazuh process alerts
  * cpu_pct, mem_pct                                <- `docker stats` for the main container
  * outbound_conns                                  <- `docker exec ... ss`/netstat count

This module is intentionally forgiving: if a source is unavailable it contributes 0,
so the controller never crashes because a log rotated. In experiments the harness can
bypass this and hand the controller a synthetic Window directly.
"""
from __future__ import annotations

import re
import subprocess
import time
from collections import deque
from pathlib import Path
from typing import Deque, Optional, Tuple

from .anomaly import Window
from .config import ArgusConfig

_ACCESS_RE = re.compile(r'"\w+\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+(?P<code>\d{3})')


class HostSensor:
    def __init__(self, cfg: ArgusConfig, access_log: str = "runtime/webroot/access.log",
                 window_sec: int = 60):
        self.cfg = cfg
        self.access_log = Path(access_log)
        self.window_sec = window_sec
        self._log_offset = 0

    # ---- HTTP behaviour ---------------------------------------------------
    def _http_features(self) -> Tuple[float, float, float, float]:
        if not self.access_log.exists():
            return 0.0, 0.0, 0.0, 0.0
        lines = self.access_log.read_text(errors="ignore").splitlines()
        recent = lines[self._log_offset:]
        self._log_offset = len(lines)
        n = len(recent)
        if n == 0:
            return 0.0, 0.0, 0.0, 0.0
        paths, c4, c5 = set(), 0, 0
        for ln in recent:
            m = _ACCESS_RE.search(ln)
            if not m:
                continue
            paths.add(m.group("path"))
            code = m.group("code")
            if code.startswith("4"):
                c4 += 1
            elif code.startswith("5"):
                c5 += 1
        per_min = n * (60.0 / self.window_sec)
        return per_min, float(len(paths)), c4 / n, c5 / n

    # ---- Wazuh alert counts ----------------------------------------------
    def _fim_process_counts(self) -> Tuple[float, float]:
        p = Path(self.cfg.wazuh_alerts_path)
        if not p.exists():
            return 0.0, 0.0
        fim = proc = 0
        for ln in p.read_text(errors="ignore").splitlines()[-500:]:
            if "syscheck" in ln:
                fim += 1
            if "process" in ln or "audit" in ln:
                proc += 1
        return float(fim), float(proc)

    # ---- container resource use ------------------------------------------
    def _resource_features(self) -> Tuple[float, float, float]:
        try:
            out = subprocess.run(
                ["docker", "stats", "--no-stream", "--format",
                 "{{.CPUPerc}};{{.MemPerc}}", self.cfg.protected_container],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            cpu, mem = out.split(";")
            cpu_pct = float(cpu.strip().rstrip("%") or 0)
            mem_pct = float(mem.strip().rstrip("%") or 0)
        except Exception:
            cpu_pct = mem_pct = 0.0
        try:
            conns = subprocess.run(
                ["docker", "exec", self.cfg.protected_container, "sh", "-c",
                 "ss -tn state established 2>/dev/null | wc -l"],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
            outbound = float(conns or 0)
        except Exception:
            outbound = 0.0
        return cpu_pct, mem_pct, outbound

    # ---- assemble ---------------------------------------------------------
    def window(self) -> Optional[Window]:
        req, paths, r4, r5 = self._http_features()
        fim, proc = self._fim_process_counts()
        cpu, mem, out = self._resource_features()
        return Window([req, paths, r4, r5, fim, proc, cpu, mem, out])

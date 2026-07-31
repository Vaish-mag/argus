"""
anomaly.py
==========
The project's ML component: an unsupervised anomaly detector that catches attack
patterns the signature engine has never seen.

Design choices you can defend in a viva:
  * Unsupervised (IsolationForest) -- we cannot enumerate every future attack, so we
    model "normal" and flag deviation, rather than training on a labelled attack set
    we do not have.
  * IsolationForest specifically -- linear-time, tiny memory, no feature scaling
    required, works on a laptop, and its anomaly score is directly interpretable as a
    ranking. (An autoencoder is the natural next step; noted in Future Work.)
  * Windowed features over the *behaviour* of the protected service, not raw packets,
    so the model stays small and the features are explainable:

        [ req_per_min, unique_paths, rate_4xx, rate_5xx,
          file_change_events, new_process_events, cpu_pct, mem_pct, outbound_conns ]

The detector is trained on baseline (normal-traffic) windows collected before any
attack, then scores each live window. A window scoring below the configured threshold
is emitted as an anomaly signal to detector.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    import joblib
    _HAVE_SKLEARN = True
except ImportError:  # pragma: no cover
    _HAVE_SKLEARN = False


FEATURE_NAMES: List[str] = [
    "req_per_min", "unique_paths", "rate_4xx", "rate_5xx",
    "file_change_events", "new_process_events", "cpu_pct", "mem_pct", "outbound_conns",
]


@dataclass
class Window:
    """One time-window of observed behaviour."""
    values: Sequence[float]

    def vector(self) -> List[float]:
        v = list(self.values)
        if len(v) != len(FEATURE_NAMES):
            raise ValueError(f"expected {len(FEATURE_NAMES)} features, got {len(v)}")
        return v


class AnomalyDetector:
    def __init__(self, contamination: float = 0.02, random_state: int = 42):
        if not _HAVE_SKLEARN:
            raise RuntimeError("scikit-learn is required for AnomalyDetector")
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )
        self._fitted = False

    def fit(self, windows: Sequence[Window]) -> "AnomalyDetector":
        X = np.array([w.vector() for w in windows], dtype=float)
        self.model.fit(X)
        self._fitted = True
        return self

    def score(self, window: Window) -> float:
        """Higher = more normal, lower (more negative) = more anomalous."""
        if not self._fitted:
            raise RuntimeError("model not fitted")
        return float(self.model.score_samples([window.vector()])[0])

    def is_anomaly(self, window: Window, threshold: float) -> bool:
        return self.score(window) < threshold

    # ---- persistence ------------------------------------------------------
    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, path)

    @classmethod
    def load(cls, path: str | Path, contamination: float = 0.02) -> "AnomalyDetector":
        obj = cls(contamination=contamination)
        obj.model = joblib.load(path)
        obj._fitted = True
        return obj

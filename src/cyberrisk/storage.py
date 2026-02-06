from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


RUNS_DIR = Path("data") / "runs"
LATEST_PATH = RUNS_DIR / "latest.json"


def save_run(run: Dict[str, Any]) -> Path:
    """
    Save a run payload to:
      - data/runs/<run_id>.json
      - data/runs/latest.json (pointer to the most recent run)

    Returns:
        Path to the saved <run_id>.json file.
    """
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    run_id = run.get("run_id") or str(uuid.uuid4())
    run["run_id"] = run_id
    run.setdefault("generated_at", datetime.now(timezone.utc).isoformat())

    out_path = RUNS_DIR / f"{run_id}.json"
    out_path.write_text(json.dumps(run, indent=2, ensure_ascii=False), encoding="utf-8")

    # Write/update a stable "latest.json" so the UI can always load the newest run
    LATEST_PATH.write_text(json.dumps(run, indent=2, ensure_ascii=False), encoding="utf-8")

    return out_path


def load_latest_run() -> Optional[Dict[str, Any]]:
    """
    Load the most recent run payload.

    Prefers data/runs/latest.json if present; otherwise falls back to newest *.json.
    Returns:
        Dict payload or None if no runs exist.
    """
    if LATEST_PATH.exists():
        return json.loads(LATEST_PATH.read_text(encoding="utf-8"))

    if not RUNS_DIR.exists():
        return None

    run_files = [p for p in RUNS_DIR.glob("*.json") if p.name != "latest.json"]
    if not run_files:
        return None

    newest = max(run_files, key=lambda p: p.stat().st_mtime)
    return json.loads(newest.read_text(encoding="utf-8"))

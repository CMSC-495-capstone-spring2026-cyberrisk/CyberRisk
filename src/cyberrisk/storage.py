from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


RUNS_DIR = Path("data") / "runs"


def save_run(run: Dict[str, Any]) -> str:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)

    run_id = run.get("run_id") or str(uuid.uuid4())
    run["run_id"] = run_id
    run.setdefault("generated_at", datetime.now(timezone.utc).isoformat())

    out_path = RUNS_DIR / f"{run_id}.json"
    out_path.write_text(json.dumps(run, indent=2, ensure_ascii=False), encoding="utf-8")
    return run_id

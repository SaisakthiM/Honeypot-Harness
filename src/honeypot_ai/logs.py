"""Three-level logging.

raw.jsonl    every model request/response, tool call, tool result, fetched page
chain.jsonl  ordered, categorised steps (task, model_turn, tool_call, decoy_hit, ...)
report.json / report.md   final incident summary (written by report.py)
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path


class RunLog:
    def __init__(self, base_dir, run_id=None):
        base = run_id or (time.strftime("%H%M%S") + "-" + uuid.uuid4().hex[:6])
        rid, n = base, 1
        while (Path(base_dir) / rid).exists():
            n += 1
            rid = f"{base}-{n}"
        self.run_id = rid
        self.dir = Path(base_dir) / rid
        self.dir.mkdir(parents=True, exist_ok=True)
        self._raw = open(self.dir / "raw.jsonl", "a", encoding="utf-8")
        self._chain = open(self.dir / "chain.jsonl", "a", encoding="utf-8")
        self.chain_events = []
        self._seq = 0
        self._t0 = time.time()

    def raw(self, event, **data):
        rec = {"t": round(time.time() - self._t0, 4), "event": event, **data}
        self._raw.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        self._raw.flush()

    def chain(self, category, **data):
        self._seq += 1
        rec = {"step": self._seq, "category": category, **data}
        self.chain_events.append(rec)
        self._chain.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        self._chain.flush()
        return rec

    def close(self):
        for f in (self._raw, self._chain):
            try:
                f.close()
            except Exception:
                pass

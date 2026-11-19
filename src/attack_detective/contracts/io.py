"""JSON-lines helpers (one JSON object per line)."""
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Iterable, List


def write_jsonl(records: Iterable, path) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            obj = asdict(r) if is_dataclass(r) else r
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
            n += 1
    return n


def read_jsonl(path) -> List[dict]:
    with Path(path).open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]

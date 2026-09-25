import json
from pathlib import Path

from ..models import ScanResult


def render_json(results: list[ScanResult] | ScanResult) -> str:
    values = results if isinstance(results, list) else [results]
    payload = [r.to_dict() for r in values]
    return json.dumps(payload[0] if len(payload) == 1 else payload, indent=2, ensure_ascii=False)


def write_json(results, path: str) -> None:
    Path(path).write_text(render_json(results) + "\n", encoding="utf-8")

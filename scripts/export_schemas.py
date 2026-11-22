"""Write the JSON schemas generated from Probe's Pydantic models.

uv run python scripts/export_schemas.py            # (re)write schemas/*.json
uv run python scripts/export_schemas.py --check    # exit 1 if a committed schema is stale
"""

import argparse
import json
import sys
from pathlib import Path

from pydantic import BaseModel

from probe.report.models import ScanReport

ROOT = Path(__file__).resolve().parent.parent

# File name -> model. The profile schema is added with the profile model (task T18).
SCHEMAS: dict[str, type[BaseModel]] = {
    "report.schema.json": ScanReport,
}


def render(model: type[BaseModel]) -> str:
    schema = model.model_json_schema(mode="serialization")
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if schemas are out of date")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "schemas")
    args = parser.parse_args()

    stale = []
    for name, model in SCHEMAS.items():
        path = args.out_dir / name
        expected = render(model)
        if args.check:
            if not path.exists() or path.read_text() != expected:
                stale.append(name)
        else:
            args.out_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(expected)
            print(f"wrote {path}")
    if stale:
        print(f"stale schemas: {', '.join(stale)} (run: uv run python scripts/export_schemas.py)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

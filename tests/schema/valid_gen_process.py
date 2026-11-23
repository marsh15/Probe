"""Exercise the public generator in a fresh interpreter for determinism checks."""

import json
import sys
from pathlib import Path

from probe.classify.tools import classify_tool
from probe.schema.valid_gen import generate_valid
from probe.util.canonical_json import canonical_json


def main():
    fixtures = Path(__file__).resolve().parents[2] / "fixtures" / "schemas"
    output = {}
    for path in sorted(fixtures.glob("*.json")):
        tool = classify_tool(path.stem, json.loads(path.read_text()))
        generated = generate_valid(tool, seed=int(sys.argv[1]), mode="quick")
        output[path.stem] = [[case.id, case.arguments] for case in generated.cases]
    sys.stdout.buffer.write(canonical_json(output).encode("utf-8", "surrogatepass"))


if __name__ == "__main__":
    main()

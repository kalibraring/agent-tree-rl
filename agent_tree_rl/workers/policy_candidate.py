#!/usr/bin/env python3
"""Run one hidden evaluation case against one immutable policy artifact."""

from __future__ import annotations

import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent_tree_rl.engine import PUCTSearch, default_benchmark, default_scenario  # noqa: E402
from agent_tree_rl.serde import model_from_payload  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: policy_candidate.py POLICY_ARTIFACT")
    artifact = Path(sys.argv[1]).resolve(strict=True)
    model_payload = json.loads(artifact.read_text(encoding="utf-8"))
    model = model_from_payload(model_payload)
    envelope = json.load(sys.stdin)
    request = envelope["input"]
    if request.get("operation") != "policy-search":
        result: object = {"error": "unsupported operation"}
    else:
        seed = int(request["seed"])
        simulations = int(request["simulations"])
        scenario = default_scenario()
        search = PUCTSearch(
            scenario,
            default_benchmark(scenario),
            model,
            seed=seed,
        ).run(simulations)
        result = {
            "trajectory": [move.id for move in search.trajectory],
            "feasible": search.score.feasible,
            "abstained": search.abstained,
        }
    json.dump(
        {"output": result},
        sys.stdout,
        sort_keys=True,
        separators=(",", ":"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

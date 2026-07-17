#!/usr/bin/env python3
"""Reference candidate for the private benchmark protocol.

The candidate sees one case input per process. It never sees expected outputs.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    envelope = json.load(sys.stdin)
    request = envelope["input"]
    operation = request.get("operation")
    if operation == "sum":
        result = sum(request["values"])
    elif operation == "choose":
        result = max(request["options"], key=lambda item: item["score"])
    elif operation == "threshold":
        result = {
            "decision": (
                "proceed"
                if request["confidence_ppm"] >= request["minimum_ppm"]
                else "abstain"
            )
        }
    else:
        result = {"error": "unsupported operation"}
    json.dump(
        {"output": result},
        sys.stdout,
        sort_keys=True,
        separators=(",", ":"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

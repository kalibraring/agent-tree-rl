#!/usr/bin/env python3
"""Require immutable, aligned application and proxy image references."""

from __future__ import annotations

from pathlib import Path
import re


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PINNED_IMAGE = re.compile(
    r"^[a-z0-9][a-z0-9./_-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$"
)


def _one(pattern: str, text: str, *, source: str) -> str:
    matches = re.findall(pattern, text)
    if len(matches) != 1:
        raise SystemExit(f"expected one {source} image default, found {len(matches)}")
    return matches[0]


def main() -> int:
    dockerfile = (PROJECT_ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8")
    compose = (PROJECT_ROOT / "deploy" / "compose.yaml").read_text(encoding="utf-8")
    docker_python = _one(
        r"(?m)^ARG PYTHON_IMAGE=(\S+)$",
        dockerfile,
        source="Dockerfile Python",
    )
    compose_python = _one(
        r"\$\{PYTHON_IMAGE:-([^}]+)\}",
        compose,
        source="Compose Python",
    )
    compose_caddy = _one(
        r"\$\{CADDY_IMAGE:-([^}]+)\}",
        compose,
        source="Compose Caddy",
    )
    for label, image in (
        ("Dockerfile Python", docker_python),
        ("Compose Python", compose_python),
        ("Compose Caddy", compose_caddy),
    ):
        if PINNED_IMAGE.fullmatch(image) is None:
            raise SystemExit(f"{label} image is not tag-and-digest pinned: {image}")
    if docker_python != compose_python:
        raise SystemExit("Dockerfile and Compose Python image pins differ")
    print("deployment pin check passed: application and proxy images are immutable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

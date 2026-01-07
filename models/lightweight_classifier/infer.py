"""Inference entry point for the lightweight classifier."""

from __future__ import annotations

from typing import Dict


def infer(text: str) -> Dict[str, float]:
    raise NotImplementedError("Inference pipeline not implemented yet")


if __name__ == "__main__":
    sample = "example"
    print(infer(sample))

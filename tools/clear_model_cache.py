"""Utility for clearing local Hugging Face model cache."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil


def get_hf_cache_dir() -> Path:
    cache_override = os.getenv("HUGGINGFACE_HUB_CACHE") or os.getenv("TRANSFORMERS_CACHE")
    if cache_override:
        return Path(cache_override).expanduser()

    hf_home = os.getenv("HF_HOME")
    if hf_home:
        return Path(hf_home).expanduser() / "hub"

    return Path.home() / ".cache" / "huggingface" / "hub"


def _model_cache_dir(cache_dir: Path, model_id: str) -> Path:
    normalized = model_id.strip().replace("/", "--")
    return cache_dir / f"models--{normalized}"


def clear_cache(model_id: str | None, all_cache: bool) -> Path | None:
    cache_dir = get_hf_cache_dir()
    if all_cache:
        if not cache_dir.exists():
            return None
        shutil.rmtree(cache_dir)
        return cache_dir

    if not model_id:
        raise ValueError("model_id is required unless --all is set")

    model_dir = _model_cache_dir(cache_dir, model_id)
    if not model_dir.exists():
        return None
    shutil.rmtree(model_dir)
    return model_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Clear local Hugging Face model cache.")
    parser.add_argument(
        "--model",
        help="Model id to remove (e.g. Qwen/Qwen2.5-1.5B-Instruct).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Remove the entire Hugging Face hub cache directory.",
    )
    args = parser.parse_args()

    if args.all and args.model:
        parser.error("Use --all or --model, not both.")

    try:
        removed = clear_cache(args.model, args.all)
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    if removed is None:
        print("Nothing to remove.")
        return 0

    print(f"Removed cache at: {removed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

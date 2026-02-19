#!/usr/bin/env python3
"""Lightweight SkillsBench skill list/install utility."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile

DEFAULT_REPO = "benchflow-ai/skillsbench"
DEFAULT_REF = "main"
DEFAULT_DEST = "skills"
SKILL_FILE_SUFFIX = "/SKILL.md"
SKILL_SEGMENT = "/environment/skills/"


class SkillInstallError(RuntimeError):
    pass


def _request(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "argis-skillsbench-manager",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return response.read()


def _fetch_tree(repo: str, ref: str) -> list[str]:
    encoded_ref = urllib.parse.quote(ref, safe="")
    url = f"https://api.github.com/repos/{repo}/git/trees/{encoded_ref}?recursive=1"
    payload = json.loads(_request(url).decode("utf-8"))
    tree = payload.get("tree")
    if not isinstance(tree, list):
        raise SkillInstallError("Unexpected GitHub tree response.")
    paths: list[str] = []
    for item in tree:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "blob":
            continue
        path = item.get("path")
        if isinstance(path, str):
            paths.append(path)
    return paths


def _path_priority(path: str) -> tuple[int, int, int, str]:
    if path.startswith("tasks/"):
        rank = 0
    elif path.startswith("tasks-no-skills/"):
        rank = 1
    elif path.startswith("tasks_no_skills_generate/"):
        rank = 2
    else:
        rank = 3
    return (rank, path.count("/"), len(path), path)


def _discover_remote_skill_paths(repo: str, ref: str) -> dict[str, str]:
    skill_candidates: dict[str, list[str]] = {}
    for path in _fetch_tree(repo, ref):
        if not path.endswith(SKILL_FILE_SUFFIX):
            continue
        if SKILL_SEGMENT not in path:
            continue
        folder = path[: -len(SKILL_FILE_SUFFIX)]
        skill_name = folder.rsplit("/", 1)[-1].strip()
        if not skill_name:
            continue
        skill_candidates.setdefault(skill_name, []).append(folder)

    if not skill_candidates:
        raise SkillInstallError("No skills found in remote repository.")

    selected: dict[str, str] = {}
    for skill_name, options in skill_candidates.items():
        selected[skill_name] = sorted(options, key=_path_priority)[0]
    return dict(sorted(selected.items()))


def _safe_extract_zip(archive: zipfile.ZipFile, destination: Path) -> None:
    root = destination.resolve()
    for info in archive.infolist():
        target = (destination / info.filename).resolve()
        if target == root or root in target.parents:
            continue
        raise SkillInstallError("Archive contains invalid paths.")
    archive.extractall(destination)


def _download_repo_zip(repo: str, ref: str) -> bytes:
    if "/" not in repo:
        raise SkillInstallError("Repo must be in owner/repo format.")
    owner, name = repo.split("/", 1)
    url = f"https://codeload.github.com/{owner}/{name}/zip/{ref}"
    return _request(url)


def _install_skills(
    *,
    repo: str,
    ref: str,
    selected_paths: dict[str, str],
    names: list[str],
    dest: Path,
    force: bool,
) -> list[str]:
    missing = [name for name in names if name not in selected_paths]
    if missing:
        raise SkillInstallError(f"Unknown skills: {', '.join(missing)}")

    payload = _download_repo_zip(repo, ref)
    installed: list[str] = []
    with tempfile.TemporaryDirectory(prefix="argis-skillsbench-") as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            _safe_extract_zip(archive, tmp_dir)
            roots = sorted({item.split("/", 1)[0] for item in archive.namelist() if item})
        if len(roots) != 1:
            raise SkillInstallError("Unexpected archive layout.")
        repo_root = tmp_dir / roots[0]

        dest.mkdir(parents=True, exist_ok=True)
        for skill_name in names:
            source = repo_root / selected_paths[skill_name]
            if not source.is_dir():
                raise SkillInstallError(f"Skill source not found in archive: {selected_paths[skill_name]}")
            destination = dest / skill_name
            if destination.exists():
                if force:
                    shutil.rmtree(destination)
                else:
                    raise SkillInstallError(f"Destination already exists: {destination}")
            shutil.copytree(source, destination)
            installed.append(skill_name)
            print(f"Installed {skill_name} -> {destination}")
    return installed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage local skills from SkillsBench.")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="Remote repo in owner/repo format.")
    parser.add_argument("--ref", default=DEFAULT_REF, help="Git ref to fetch from.")
    parser.add_argument("--dest", default=DEFAULT_DEST, help="Destination skills directory.")
    parser.add_argument("--list", action="store_true", help="List available remote skills.")
    parser.add_argument("--install", nargs="+", metavar="SKILL", help="Install one or more skills by name.")
    parser.add_argument("--force", action="store_true", help="Overwrite existing local skills.")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser


def main(argv: list[str]) -> int:
    args = _build_parser().parse_args(argv)
    try:
        selected_paths = _discover_remote_skill_paths(args.repo, args.ref)
        if args.list or not args.install:
            if args.json:
                print(json.dumps(selected_paths, ensure_ascii=True, indent=2))
            else:
                print(f"Skills from {args.repo}@{args.ref}:")
                for idx, (name, path) in enumerate(selected_paths.items(), start=1):
                    print(f"{idx}. {name} ({path})")
            return 0

        installed = _install_skills(
            repo=args.repo,
            ref=args.ref,
            selected_paths=selected_paths,
            names=args.install,
            dest=Path(args.dest),
            force=bool(args.force),
        )
        if args.json:
            print(json.dumps({"installed": installed, "dest": args.dest}, ensure_ascii=True))
        return 0
    except SkillInstallError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

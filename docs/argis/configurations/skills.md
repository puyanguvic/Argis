---
title: Skills
description: Skillpack structure, installation workflow, runtime discovery, and operational guidance for Argis local skills.
---

# Skills

Argis supports local skillpacks under `skillpacks/`.

## What Skillpacks Are For

Skillpacks extend local instructions and capability workflows without collapsing policy, runtime control, and execution into a single opaque unit. In this repository they are discovered from local directories and surfaced as runtime metadata, rather than being silently inlined into the control stack.

## Format

- one folder per skillpack
- skill instructions in `SKILL.md`

The lightweight directory-based format is intentional. It keeps skill definitions inspectable, versionable, and reviewable alongside the main repository.

## Install and Update

List installable skillpacks:

```bash
python scripts/skillsbench_skillpacks.py --list
```

Install selected skillpacks:

```bash
python scripts/skillsbench_skillpacks.py --install threat-detection openai-vision image-ocr
```

## Runtime Behavior

- runtime auto-discovers local skillpacks in `skillpacks/`
- override discovery path with `MY_AGENT_APP_SKILLPACKS_DIR`

At runtime, discovered skillpacks are reported in metadata rather than hidden behind implicit loading. This is important for auditability: operators can see which skillpacks were available when a result was produced.

## When To Add A Skillpack

Add or update a skillpack when you need:

- specialized local instructions that do not belong in the core product docs
- a workflow extension that should remain explicit and inspectable
- a capability bundle that is useful across repeated operator tasks

Do not use skillpacks as a shortcut for bypassing architecture boundaries. Policy and orchestrator responsibilities still belong in the core codebase.

## Operational Guidance

- treat installed skillpacks as runtime-affecting inputs
- document skillpack changes when they alter workflows or operator expectations
- surface skillpack names in debugging, evaluation, or analyst contexts when relevant

Related docs:

- [Using Argis](/argis/using-argis/)
- [Agents.md](/argis/configurations/agents-md)
- [Context Management](/argis/configurations/context-management)

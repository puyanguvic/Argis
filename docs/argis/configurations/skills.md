# Skills

Argis supports local skillpacks under `skillpacks/`.

## Format

- one folder per skillpack
- skill instructions in `SKILL.md`

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

Reference: [Manual](/manual).

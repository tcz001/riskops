# PAI Distillation Examples

This directory contains generated artifacts for the security-judge distillation track.

- `instruction_only.jsonl` is the PAI Model Gallery distillation input.
- `labeled_companion.jsonl` is a local companion dataset for validation and QA.
- `manifest.json` records the generation inputs and output paths.

Generate the files from the repo root:

```bash
python3 tools/pai_distillation/generate_dataset.py
```

You can override the defaults if you want to write into OSS staging directories first:

```bash
python3 tools/pai_distillation/generate_dataset.py \
  --seed-file examples/pai/security_judge_seeds.jsonl \
  --instruction-output examples/pai/distillation/instruction_only.jsonl \
  --labeled-output examples/pai/distillation/labeled_companion.jsonl \
  --manifest-output examples/pai/distillation/manifest.json
```


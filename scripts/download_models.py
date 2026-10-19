"""Download Qwen3Guard-Gen-0.6B, Qwen3Guard-Stream-0.6B, and Qwen3-0.6B into ./models."""
from __future__ import annotations

import os
from pathlib import Path
from huggingface_hub import snapshot_download

ROOT_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = Path(os.environ.get("QWENGUARD_MODEL_ROOT", str(ROOT_DIR / "models")))

MODELS = [
    ("Qwen/Qwen3Guard-Gen-0.6B", "Qwen3Guard-Gen-0.6B"),
    ("Qwen/Qwen3Guard-Stream-0.6B", "Qwen3Guard-Stream-0.6B"),
    ("Qwen/Qwen3-0.6B", "Qwen3-0.6B"),
]


def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    for repo_id, local_name in MODELS:
        target = MODELS_DIR / local_name
        print(f"[+] Downloading {repo_id} -> {target} ...")
        snapshot_download(
            repo_id=repo_id,
            local_dir=str(target),
            local_dir_use_symlinks=False,
        )
        print(f"[✓] Finished {local_name}")


if __name__ == "__main__":
    main()

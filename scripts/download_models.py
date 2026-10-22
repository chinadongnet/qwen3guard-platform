"""CLI helper to pre-download Qwen3Guard and Qwen3 models from ModelScope or HuggingFace."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent

MODELS = {
    "Qwen3Guard-Gen-0.6B": "Qwen/Qwen3Guard-Gen-0.6B",
    "Qwen3Guard-Stream-0.6B": "Qwen/Qwen3Guard-Stream-0.6B",
    "Qwen3-0.6B": "Qwen/Qwen3-0.6B",
}


def download_models(output_dir: Path, source: str = "modelscope") -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"Target directory : {output_dir}")
    print(f"Download source  : {source}")
    print("=" * 60)

    for name, repo_id in MODELS.items():
        target = output_dir / name
        if target.exists() and any(target.iterdir()):
            print(f"[SKIP] {name} already exists at {target}")
            continue

        print(f"[DOWNLOADING] {name} from {source} ({repo_id})...")
        if source == "modelscope":
            try:
                from modelscope.hub.snapshot_download import snapshot_download
                path = snapshot_download(repo_id, local_dir=str(target))
                print(f"[SUCCESS] Downloaded {name} to {path}")
            except Exception as e:
                print(f"[ERROR] Failed to download {name} via ModelScope: {e}", file=sys.stderr)
        else:
            try:
                from huggingface_hub import snapshot_download
                path = snapshot_download(repo_id=repo_id, local_dir=str(target))
                print(f"[SUCCESS] Downloaded {name} to {path}")
            except Exception as e:
                print(f"[ERROR] Failed to download {name} via HuggingFace: {e}", file=sys.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download Qwen3Guard Suite models.")
    parser.add_argument("--output-dir", type=Path, default=ROOT_DIR / "models", help="Directory to save models")
    parser.add_argument("--source", choices=["modelscope", "huggingface"], default="modelscope", help="Download source")
    args = parser.parse_args()
    download_models(args.output_dir, args.source)

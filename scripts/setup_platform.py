"""Create local deployment secrets and a dated backup without overwriting existing files."""
from pathlib import Path
import json
import secrets
import shutil
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def main():
    env = ROOT / ".env"
    if env.exists():
        print(".env already exists; no credentials changed.")
        return
    backup = ROOT / "data" / "backups" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup.mkdir(parents=True, exist_ok=False)
    manifest = []
    for source in (ROOT / "data").glob("*.json"):
        shutil.copy2(source, backup / source.name)
        manifest.append({"name": source.name, "bytes": source.stat().st_size})
    (backup / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    password = secrets.token_urlsafe(24)
    values = {
        "DATABASE_URL": "sqlite:///data/platform.db",
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "PLATFORM_SECRET": secrets.token_urlsafe(48),
        "BOOTSTRAP_ADMIN_USER": "admin",
        "BOOTSTRAP_ADMIN_PASSWORD": password,
        "COOKIE_SECURE": "false",
        "ALLOWED_ORIGINS": "",
        "ALLOWED_PRIVATE_HOSTS": "",
    }
    with env.open("x", encoding="utf-8") as handle:
        handle.write("\n".join(f"{key}={value}" for key, value in values.items()) + "\n")
    credentials = ROOT / "data" / "bootstrap-credentials.txt"
    with credentials.open("x", encoding="utf-8") as handle:
        handle.write(f"QwenGuard administrator\nURL: http://127.0.0.1:8092\nUsername: admin\nPassword: {password}\n")
    try:
        env.chmod(0o600)
        credentials.chmod(0o600)
    except OSError:
        pass
    print("Deployment secrets created in .env (gitignored).")
    print("Administrator credentials: data/bootstrap-credentials.txt (gitignored).")
    print(f"Legacy data backup: {backup.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

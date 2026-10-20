from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.getenv(
        "DATABASE_URL", "sqlite:///data/platform.db"))
    secret: str = field(default_factory=lambda: os.getenv("PLATFORM_SECRET", ""))
    admin_user: str = field(default_factory=lambda: os.getenv("BOOTSTRAP_ADMIN_USER", "admin"))
    admin_password: str = field(default_factory=lambda: os.getenv("BOOTSTRAP_ADMIN_PASSWORD", ""))
    secure_cookie: bool = field(default_factory=lambda: os.getenv("COOKIE_SECURE", "false").lower() == "true")
    allowed_origins: tuple = field(default_factory=lambda: tuple(
        x.strip() for x in os.getenv("ALLOWED_ORIGINS", "").split(",") if x.strip()))
    private_hosts: tuple = field(default_factory=lambda: tuple(
        x.strip().lower() for x in os.getenv("ALLOWED_PRIVATE_HOSTS", "").split(",") if x.strip()))
    inference_capacity: int = 8
    inference_timeout: float = 30
    audit_raw_retention_days: int = field(default_factory=lambda: int(os.getenv("AUDIT_RAW_RETENTION_DAYS", "7")))
    session_seconds: int = 28800
    testing: bool = False
    static_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parents[1] / "console")

    def validate(self):
        if not 1 <= self.audit_raw_retention_days <= 365:
            raise RuntimeError("AUDIT_RAW_RETENTION_DAYS must be between 1 and 365")
        if len(self.secret) < 32:
            raise RuntimeError("PLATFORM_SECRET must contain at least 32 characters; run scripts/setup_platform.py")
        if self.admin_password and len(self.admin_password) < 12:
            raise RuntimeError("Bootstrap password must contain at least 12 characters")

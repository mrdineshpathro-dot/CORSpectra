"""YAML and programmatic configuration with strict validation."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "corspectra" / "config.yaml"


@dataclass(slots=True)
class Config:
    timeout: float = 10.0
    threads: int = 10
    retries: int = 2
    rate_limit: float = 10.0
    delay: float = 0.0
    user_agent: str = "CORSpectra/1.0.0 (authorized security audit)"
    follow_redirects: bool = False
    verify_ssl: bool = True
    crawl: bool = False
    crawl_depth: int = 1
    max_pages: int = 50
    origins: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    output_directory: str = "reports"

    def validate(self) -> Config:
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        if not 1 <= self.threads <= 100:
            raise ValueError("threads must be between 1 and 100")
        if not 0 <= self.retries <= 10:
            raise ValueError("retries must be between 0 and 10")
        if self.rate_limit < 0 or self.delay < 0:
            raise ValueError("rate limits cannot be negative")
        if self.crawl_depth < 0 or self.max_pages < 1:
            raise ValueError("invalid crawler limits")
        return self

    @classmethod
    def load(cls, path: Path | str | None = None) -> Config:
        config_path = Path(path) if path else DEFAULT_CONFIG_PATH
        if not config_path.exists():
            return cls()
        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML configuration: {exc}") from exc
        if not isinstance(raw, dict):
            raise TypeError("configuration root must be a mapping")
        allowed = {f.name for f in fields(cls)}
        unknown = set(raw) - allowed
        if unknown:
            raise ValueError(f"unknown configuration options: {', '.join(sorted(unknown))}")
        return cls(**raw).validate()

    def merge(self, **overrides: Any) -> Config:
        values = {f.name: getattr(self, f.name) for f in fields(self)}
        values.update({k: v for k, v in overrides.items() if v is not None})
        return Config(**values).validate()

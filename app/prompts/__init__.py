"""Versioned system prompts.

Each prompt lives in its own immutable file (``v1.md``, ``v2.md`` ...). A prompt change is
shipped as a NEW file, never an edit of an existing one, so tenants pinned to an older
version keep exactly the behaviour they had.
"""

from __future__ import annotations

import hashlib
import re
from functools import cache
from pathlib import Path

PROMPT_DIR = Path(__file__).resolve().parent
_VERSION_RE = re.compile(r"^v\d+$")


class UnknownPromptVersionError(LookupError):
    pass


def available_versions() -> list[str]:
    return sorted((p.stem for p in PROMPT_DIR.glob("v*.md") if _VERSION_RE.match(p.stem)), key=lambda v: int(v[1:]))


@cache
def get_prompt(version: str) -> str:
    if not _VERSION_RE.match(version or ""):
        raise UnknownPromptVersionError(version)
    path = PROMPT_DIR / f"{version}.md"
    if not path.is_file():
        raise UnknownPromptVersionError(version)
    return path.read_text(encoding="utf-8").strip()


def prompt_fingerprint(version: str) -> str:
    """Short content hash; logged with every request so behaviour is traceable to exact text."""
    return hashlib.sha256(get_prompt(version).encode()).hexdigest()[:12]

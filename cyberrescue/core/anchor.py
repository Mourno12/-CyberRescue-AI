"""External, keyed audit anchors (Phase 7) - key handling.

The Core's audit log is a SHA-256 hash chain: tamper-EVIDENT, but someone who
can write the database file can drop the triggers, rewrite history and
recompute every hash. Phase 7 adds anchors: checkpoints of the chain heads,
signed with HMAC-SHA256 under a key that lives OUTSIDE the database and the
repository, and stored by the operator outside the attacker's reach.

This module part handles the key:

* ``generate_key`` - ``secrets.token_bytes(32)``;
* ``write_new_key`` - writes a new key file; refuses to overwrite and refuses
  any path inside the repository;
* ``load_key`` - from ``--key-file`` or ``$CYBERRESCUE_ANCHOR_KEY_FILE`` (a
  PATH; a raw key in the environment is deliberately not supported); refuses
  missing, unreadable, malformed, weak and in-repository keys.

The key never leaves an ``AnchorKey``: its ``repr``/``str`` are redacted, it
cannot be pickled or copied into JSON, and every error message is a fixed
text raised ``from None`` - no key material is echoed or chained.

Key file format (ASCII)::

    cyberrescue-anchor-key/1
    <at least 64 lowercase hex characters>
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

from cyberrescue.core.db import REPO_ROOT

KEY_FILE_ENV = "CYBERRESCUE_ANCHOR_KEY_FILE"
KEY_HEADER = "cyberrescue-anchor-key/1"
KEY_BYTES = 32                 # generated length
MIN_KEY_BYTES = 32             # accepted minimum
MIN_DISTINCT_BYTES = 16        # a random 32-byte key has ~30; patterns have few
_HEX_RE = re.compile(r"^(?:[0-9a-f]{2})+$")


class AnchorKeyError(ValueError):
    """The anchor key is missing, unreadable, malformed, weak or misplaced.
    Messages never contain key material."""


class AnchorKey:
    """An HMAC key held in memory only. Never printed, logged or serialised."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        _check_strength(key)
        object.__setattr__(self, "_key", bytes(key))

    def __setattr__(self, name, value):
        raise AttributeError("AnchorKey is immutable")

    def __repr__(self) -> str:
        return "AnchorKey(<redacted>)"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("an AnchorKey cannot be serialised")

    def __eq__(self, other: object) -> bool:
        import hmac
        return isinstance(other, AnchorKey) and hmac.compare_digest(self._key, other._key)

    def __hash__(self) -> int:
        return id(self)

    def __len__(self) -> int:
        return len(self._key)


def _check_strength(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise AnchorKeyError("the anchor key must be bytes")
    if len(key) < MIN_KEY_BYTES:
        raise AnchorKeyError(f"the anchor key is too short (minimum {MIN_KEY_BYTES} bytes)")
    if len(set(key)) < MIN_DISTINCT_BYTES:
        raise AnchorKeyError("the anchor key is weak (too few distinct bytes); generate a new "
                             "one with `python -m cyberrescue.core anchor-keygen`")


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def _inside(path: Path, root: Path) -> bool:
    p = os.path.normcase(str(path.resolve()))
    r = os.path.normcase(str(root.resolve()))
    return p == r or p.startswith(r.rstrip(os.sep) + os.sep)


def _refuse_repo(path: Path, repo_root: Path) -> None:
    if _inside(path, repo_root):
        raise AnchorKeyError("the anchor key file must not be inside the repository; keep it "
                             "outside the project (and away from the database)")


def write_new_key(path: str | Path, *, repo_root: Path = REPO_ROOT) -> Path:
    """Create a NEW key file. Refuses an existing file and any in-repository path."""
    target = Path(path)
    _refuse_repo(target, repo_root)
    if target.exists():
        raise AnchorKeyError("refusing to overwrite an existing file; choose a new path")
    key = generate_key()
    body = f"{KEY_HEADER}\n{key.hex()}\n".encode("ascii")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "xb") as f:            # exclusive create: never overwrites
            f.write(body)
    except FileExistsError:
        raise AnchorKeyError("refusing to overwrite an existing file; choose a new path") \
            from None
    except OSError:
        raise AnchorKeyError("could not write the anchor key file") from None
    try:
        os.chmod(target, 0o600)                     # best effort (no-op semantics on Windows)
    except OSError:
        pass
    return target


def resolve_key_path(key_file: str | Path | None = None) -> Path:
    """``--key-file`` if given, else ``$CYBERRESCUE_ANCHOR_KEY_FILE``."""
    raw = key_file if key_file is not None else os.getenv(KEY_FILE_ENV)
    if raw is None or not str(raw).strip():
        raise AnchorKeyError(f"no anchor key: pass --key-file or set {KEY_FILE_ENV} to the "
                             "path of a key file")
    return Path(str(raw).strip())


def load_key(key_file: str | Path | None = None, *, repo_root: Path = REPO_ROOT) -> AnchorKey:
    path = resolve_key_path(key_file)
    _refuse_repo(path, repo_root)
    if not path.is_file():
        raise AnchorKeyError("the anchor key file does not exist or is not a file")
    try:
        data = path.read_bytes()
    except OSError:
        raise AnchorKeyError("the anchor key file cannot be read") from None
    if len(data) > 4096:
        raise AnchorKeyError("the anchor key file is malformed")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise AnchorKeyError("the anchor key file is malformed") from None
    lines = text.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if len(lines) != 2 or lines[0] != KEY_HEADER or not _HEX_RE.match(lines[1]):
        raise AnchorKeyError("the anchor key file is malformed "
                             f"(expected a '{KEY_HEADER}' line and one line of lowercase hex)")
    return AnchorKey(bytes.fromhex(lines[1]))

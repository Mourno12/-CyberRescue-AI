"""External, keyed audit anchors (Phase 7).

The Core's audit log is a SHA-256 hash chain: tamper-EVIDENT, but someone who
can write the database file can drop the triggers, rewrite history and
recompute every hash. Phase 7 adds anchors: checkpoints of the chain heads,
signed with HMAC-SHA256 under a key that lives OUTSIDE the database and the
repository, and stored by the operator outside the attacker's reach.

Key handling (7-1):

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

Checkpoints (7-2): ``build_checkpoint`` reads every audit chain's head (highest
seq and its hash) - read-only. ``sign_checkpoint`` produces the signed anchor
document::

    {"checkpoint": {"schema": "cyberrescue.audit-anchor/1", "created_at": ...,
                    "schema_version": 3, "chains": {<chain>: {"seq": n, "hash": h}}},
     "hmac_sha256": <hex>}

serialised with strict canonical JSON (``anchor_json``: sorted keys, no
whitespace, ASCII escapes, no NaN). The HMAC-SHA256 input is the domain label
``cyberrescue.audit-anchor/1\\n`` followed by the canonical checkpoint bytes,
so it is unambiguous and independent of how the file is formatted.
``open_signed`` parses strictly (no duplicate keys, exact fields and types)
and compares the HMAC in constant time.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cyberrescue.core.audit import utcnow
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
        return isinstance(other, AnchorKey) and hmac.compare_digest(self._key, other._key)

    def __hash__(self) -> int:
        return id(self)

    def __len__(self) -> int:
        return len(self._key)

    def mac(self, message: bytes) -> bytes:
        """HMAC-SHA256 of ``message`` (the only use of the key)."""
        return hmac.new(self._key, message, "sha256").digest()


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


# --- checkpoints (7-2) -------------------------------------------------------------------

CHECKPOINT_SCHEMA = "cyberrescue.audit-anchor/1"
_MAC_DOMAIN = b"cyberrescue.audit-anchor/1\n"     # domain separation for the HMAC input
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_ANCHOR_CHARS = 16 * 1024 * 1024


class AnchorError(ValueError):
    """An anchor document is unusable. Messages never contain key material."""


class AnchorFormatError(AnchorError):
    """The anchor document is malformed (not a cyberrescue.audit-anchor/1 document)."""


class AnchorSignatureError(AnchorError):
    """The HMAC does not match: the anchor was altered or a different key is used."""


@dataclass(frozen=True)
class ChainHead:
    seq: int
    hash: str


@dataclass(frozen=True)
class Checkpoint:
    """The heads of every audit chain at one moment. Contains no key material."""
    created_at: str
    schema_version: int
    chains: dict[str, ChainHead] = field(default_factory=dict)
    schema: str = CHECKPOINT_SCHEMA

    def body(self) -> dict[str, Any]:
        return {"schema": self.schema, "created_at": self.created_at,
                "schema_version": self.schema_version,
                "chains": {c: {"seq": h.seq, "hash": h.hash}
                           for c, h in sorted(self.chains.items())}}


def anchor_json(obj: Any) -> str:
    """Strict canonical JSON for anchors: sorted keys, no whitespace, ASCII escapes,
    no NaN/Infinity, no silent conversion of unknown types."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False)


def _mac_input(checkpoint: Checkpoint) -> bytes:
    return _MAC_DOMAIN + anchor_json(checkpoint.body()).encode("ascii")


def build_checkpoint(conn: sqlite3.Connection, clock: Callable[[], datetime] = utcnow
                     ) -> Checkpoint:
    """Every chain's head: its highest seq and that event's hash. Read-only."""
    rows = conn.execute(
        "SELECT a.chain, a.seq, a.hash FROM audit_events a "
        "WHERE a.seq = (SELECT MAX(b.seq) FROM audit_events b WHERE b.chain = a.chain) "
        "ORDER BY a.chain").fetchall()
    version = conn.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'"
                           ).fetchone()             # positional: works with any row factory
    return Checkpoint(created_at=clock().isoformat(),
                      schema_version=int(version[0]) if version else 0,
                      chains={r[0]: ChainHead(seq=int(r[1]), hash=str(r[2])) for r in rows})


def sign_checkpoint(checkpoint: Checkpoint, key: AnchorKey) -> str:
    """The signed anchor document: canonical ASCII JSON, one line plus a newline."""
    _validate(checkpoint.body())
    tag = key.mac(_mac_input(checkpoint)).hex()
    return anchor_json({"checkpoint": checkpoint.body(), "hmac_sha256": tag}) + "\n"


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise AnchorFormatError("the anchor document is malformed: duplicate keys")
    return dict(pairs)


def _no_constants(name: str) -> Any:
    raise AnchorFormatError("the anchor document is malformed: NaN/Infinity")


def _validate(body: Any) -> Checkpoint:
    def bad(why: str) -> AnchorFormatError:
        return AnchorFormatError(f"the anchor document is malformed: {why}")

    if not isinstance(body, dict) or set(body) != {"schema", "created_at", "schema_version",
                                                    "chains"}:
        raise bad("unexpected checkpoint fields")
    if body["schema"] != CHECKPOINT_SCHEMA:
        raise bad("unknown checkpoint schema")
    if not isinstance(body["created_at"], str):
        raise bad("created_at must be a timestamp string")
    try:
        datetime.fromisoformat(body["created_at"])
    except ValueError:
        raise bad("created_at must be an ISO-8601 timestamp") from None
    sv = body["schema_version"]
    if not isinstance(sv, int) or isinstance(sv, bool) or sv < 1:
        raise bad("schema_version must be a positive integer")
    chains = body["chains"]
    if not isinstance(chains, dict):
        raise bad("chains must be an object")
    heads: dict[str, ChainHead] = {}
    for chain, head in chains.items():
        if not isinstance(chain, str) or not chain:
            raise bad("chain ids must be non-empty strings")
        if not isinstance(head, dict) or set(head) != {"seq", "hash"}:
            raise bad("each chain head must have exactly seq and hash")
        seq, digest_ = head["seq"], head["hash"]
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            raise bad("seq must be a positive integer")
        if not isinstance(digest_, str) or not _SHA256_RE.match(digest_):
            raise bad("hash must be 64 lowercase hex characters")
        heads[chain] = ChainHead(seq=seq, hash=digest_)
    return Checkpoint(created_at=body["created_at"], schema_version=sv, chains=heads)


def parse_signed(text: str) -> tuple[Checkpoint, str]:
    """Parse and structurally validate a signed anchor. Does NOT check the HMAC."""
    if not isinstance(text, str) or len(text) > MAX_ANCHOR_CHARS:
        raise AnchorFormatError("the anchor document is malformed: too large or not text")
    try:
        doc = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except AnchorError:
        raise
    except (ValueError, RecursionError):
        raise AnchorFormatError("the anchor document is not valid JSON") from None
    if not isinstance(doc, dict) or set(doc) != {"checkpoint", "hmac_sha256"}:
        raise AnchorFormatError("the anchor document is malformed: expected exactly "
                                "checkpoint and hmac_sha256")
    tag = doc["hmac_sha256"]
    if not isinstance(tag, str) or not _SHA256_RE.match(tag):
        raise AnchorFormatError("the anchor document is malformed: hmac_sha256 must be 64 "
                                "lowercase hex characters")
    return _validate(doc["checkpoint"]), tag


def open_signed(text: str, key: AnchorKey) -> Checkpoint:
    """Parse, validate and authenticate a signed anchor (constant-time comparison)."""
    checkpoint, tag = parse_signed(text)
    if not hmac.compare_digest(key.mac(_mac_input(checkpoint)), bytes.fromhex(tag)):
        raise AnchorSignatureError("the anchor's HMAC does not match: the anchor was altered "
                                   "or a different key is used")
    return checkpoint

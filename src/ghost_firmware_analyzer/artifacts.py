from __future__ import annotations

import hashlib
import math
import mimetypes
import re
from collections import Counter
from pathlib import Path


PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def read_prefix(path: Path, size: int = 64) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def detect_magic(prefix: bytes) -> str | None:
    signatures = {
        b"\x7fELF": "ELF",
        b"PK\x03\x04": "ZIP-compatible archive",
        b"ustar": "tar archive",
        b"hsqs": "SquashFS little-endian",
        b"sqsh": "SquashFS big-endian",
        b"\x1f\x8b": "gzip-compressed data",
        b"BZh": "bzip2-compressed data",
        b"\xfd7zXZ\x00": "XZ-compressed data",
        b"\x89PNG\r\n\x1a\n": "PNG image",
        b"\xca\xfe\xba\xbe": "Mach-O universal binary",
        b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
        b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
        b"MZ": "PE/COFF executable",
    }
    for signature, name in signatures.items():
        if prefix.startswith(signature) or signature == b"ustar" and prefix[257:262] == signature:
            return name
    return mimetypes.guess_type("artifact.bin")[0]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def printable_strings(data: bytes, minimum: int = 4, limit: int = 10_000) -> list[str]:
    pattern = re.compile(rb"[\x20-\x7e]{" + str(minimum).encode() + rb",}")
    return [match.group().decode("ascii", errors="replace") for match in pattern.finditer(data)][:limit]


def safe_relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)

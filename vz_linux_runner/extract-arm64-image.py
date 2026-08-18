#!/usr/bin/env python3
"""Extract a raw AArch64 Image from Alpine's EFI-wrapped vmlinuz."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import zlib


GZIP_MAGIC = b"\x1f\x8b\x08"
ARM64_IMAGE_MAGIC = b"ARMd"
ARM64_IMAGE_MAGIC_OFFSET = 56


def is_arm64_image(data: bytes) -> bool:
    end = ARM64_IMAGE_MAGIC_OFFSET + len(ARM64_IMAGE_MAGIC)
    return len(data) >= end and data[ARM64_IMAGE_MAGIC_OFFSET:end] == ARM64_IMAGE_MAGIC


def extract(source: Path) -> bytes:
    data = source.read_bytes()
    if is_arm64_image(data):
        return data

    offset = data.find(GZIP_MAGIC)
    while offset >= 0:
        try:
            candidate = zlib.decompress(data[offset:], zlib.MAX_WBITS | 16)
        except zlib.error:
            pass
        else:
            if is_arm64_image(candidate):
                return candidate
        offset = data.find(GZIP_MAGIC, offset + 1)

    raise ValueError("no gzip member containing an AArch64 Image was found")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()

    try:
        image = extract(arguments.source)
        arguments.destination.write_bytes(image)
    except (OSError, ValueError) as error:
        print(f"error: cannot extract ARM64 Image: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Lightweight fuzz of transform pipeline (D03)."""

from __future__ import annotations

import os

import pytest

pytest.importorskip("squidc5.profiles.transforms")
from squidc5.profiles.transforms import apply_decode, apply_encode


@pytest.mark.parametrize("n", range(20))
def test_random_payload_roundtrip_or_safe_fail(n: int):
    rng = os.urandom(16 + (n % 32))
    pipes = [
        [{"name": "base64"}],
        [{"name": "prepend", "value": "p"}, {"name": "base64"}],
        [{"name": "xor", "key": "k"}, {"name": "base64"}],
        [{"name": "netbios"}],
    ]
    pipe = pipes[n % len(pipes)]
    try:
        enc = apply_encode(pipe, rng)
        dec = apply_decode(pipe, enc)
        assert dec == rng
    except ValueError:
        pass


def test_unknown_transform_raises():
    with pytest.raises(ValueError, match="unknown"):
        apply_encode([{"name": "not_a_real_transform"}], b"x")

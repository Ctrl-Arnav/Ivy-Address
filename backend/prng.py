"""
Adaptive Privacy Observatory — PRNG Module (Python Mirror)

Python implementation of the same Xoshiro128** PRNG and SplitMix32 seeding
used in the browser extension (content.js). This module serves two purposes:

1. Backend verification: confirm JS and Python produce identical sequences
   from the same seed, ensuring deterministic cross-language consistency.
2. Entropy engine foundation: the PRNG is used by the entropy calculator
   to model expected perturbation distributions.

Reference: https://prng.di.unimi.it/xoshiro128starstar.c
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


def _u32(x: int) -> int:
    """Truncate to unsigned 32-bit integer."""
    return x & 0xFFFFFFFF


def _rotl32(x: int, k: int) -> int:
    """32-bit rotate left."""
    x = _u32(x)
    return _u32((x << k) | (x >> (32 - k)))


def _imul32(a: int, b: int) -> int:
    """Emulate JavaScript's Math.imul (32-bit integer multiply, lower 32 bits)."""
    # Python handles big ints natively, so we just mask to 32 bits
    return _u32(a * b)


# ---------------------------------------------------------------------------
# Xoshiro128** — 32-bit PRNG
# ---------------------------------------------------------------------------


@dataclass
class Xoshiro128StarStar:
    """
    Xoshiro128** pseudo-random number generator.

    Produces a high-quality 32-bit random stream from a 128-bit state.
    Period: 2^128 - 1. Passes BigCrush and PractRand test suites.
    """

    s: list[int] = field(default_factory=lambda: [0, 0, 0, 0])

    def __init__(self, s0: int, s1: int, s2: int, s3: int):
        self.s = [_u32(s0), _u32(s1), _u32(s2), _u32(s3)]

    def next(self) -> int:
        """Generate the next 32-bit unsigned integer."""
        s = self.s

        result = _u32(_imul32(_rotl32(_imul32(s[1], 5), 7), 9))

        t = _u32(s[1] << 9)

        s[2] = _u32(s[2] ^ s[0])
        s[3] = _u32(s[3] ^ s[1])
        s[1] = _u32(s[1] ^ s[2])
        s[0] = _u32(s[0] ^ s[3])

        s[2] = _u32(s[2] ^ t)
        s[3] = _rotl32(s[3], 11)

        return result

    def next_float(self) -> float:
        """Generate a float in [0, 1)."""
        return self.next() / 4294967296

    def clone(self) -> Xoshiro128StarStar:
        """Create a copy of this PRNG at its current state."""
        return Xoshiro128StarStar(self.s[0], self.s[1], self.s[2], self.s[3])


# ---------------------------------------------------------------------------
# Seeding — SplitMix32 expansion from a single 32-bit hash
# ---------------------------------------------------------------------------


def hash_string(s: str) -> int:
    """
    Fast 32-bit string hash (cyrb53-derived, single pass).

    Mirrors the JavaScript hashString() function in content.js exactly.
    Not cryptographic — only needs good distribution for PRNG seeding.
    """
    h1 = 0xDEADBEEF
    h2 = 0x41C6CE57

    for ch in s:
        c = ord(ch)
        h1 = _imul32(h1 ^ c, 0x85EBCA77)
        h2 = _imul32(h2 ^ c, 0xC2B2AE3D)

    h1 = _u32(h1 ^ _imul32(h1 ^ _u32(h2 >> 15), 0x735A2D97))
    h2 = _u32(h2 ^ _imul32(h2 ^ _u32(h1 >> 15), 0xCAF649A9))
    h1 = _u32(h1 ^ _u32(h2 >> 16))

    return h1


def splitmix32(seed: int) -> list[int]:
    """
    SplitMix32 — expand a single 32-bit seed into 4 values for Xoshiro128**.

    Mirrors the JavaScript splitmix32() function in content.js exactly.
    """
    seed = _u32(seed)
    values = []

    for _ in range(4):
        seed = _u32(seed + 0x9E3779B9)
        t = _u32(seed ^ (seed >> 16))
        t = _imul32(t, 0x21F0AAAD)
        t = _u32(t ^ (t >> 15))
        t = _imul32(t, 0x735A2D97)
        t = _u32(t ^ (t >> 15))
        values.append(t)

    return values


def create_prng(origin: str, daily_salt: str) -> Xoshiro128StarStar:
    """
    Create a deterministic PRNG seeded by origin and daily salt.

    This mirrors the JavaScript getPRNG() function in content.js.

    Args:
        origin: The page origin (e.g., "https://example.com")
        daily_salt: Date string in YYYY-MM-DD format

    Returns:
        A seeded Xoshiro128StarStar instance
    """
    seed_string = f"{origin}|{daily_salt}"
    seed_hash = hash_string(seed_string)
    expanded = splitmix32(seed_hash)
    return Xoshiro128StarStar(expanded[0], expanded[1], expanded[2], expanded[3])


# ---------------------------------------------------------------------------
# Self-test — validates PRNG produces deterministic output
# ---------------------------------------------------------------------------


def self_test():
    """Verify that the PRNG produces expected deterministic sequences."""
    # Known seed for testing
    prng = Xoshiro128StarStar(1, 2, 3, 4)
    first_10 = [prng.next() for _ in range(10)]

    # Verify determinism: same seed → same sequence
    prng2 = Xoshiro128StarStar(1, 2, 3, 4)
    first_10_again = [prng2.next() for _ in range(10)]
    assert first_10 == first_10_again, "PRNG is not deterministic!"

    # Verify domain isolation: different origins → different sequences
    prng_a = create_prng("https://tracker.com", "2026-07-14")
    prng_b = create_prng("https://example.com", "2026-07-14")
    seq_a = [prng_a.next() for _ in range(5)]
    seq_b = [prng_b.next() for _ in range(5)]
    assert seq_a != seq_b, "Different origins produced the same PRNG sequence!"

    # Verify salt rotation: same origin, different days → different sequences
    prng_day1 = create_prng("https://tracker.com", "2026-07-14")
    prng_day2 = create_prng("https://tracker.com", "2026-07-15")
    seq_day1 = [prng_day1.next() for _ in range(5)]
    seq_day2 = [prng_day2.next() for _ in range(5)]
    assert seq_day1 != seq_day2, "Different days produced the same PRNG sequence!"

    print("[PRNG Self-Test] All checks passed:")
    print(f"  Determinism:      OK (first 3: {first_10[:3]})")
    print(f"  Domain isolation:  OK")
    print(f"  Salt rotation:     OK")

    return True


if __name__ == "__main__":
    self_test()

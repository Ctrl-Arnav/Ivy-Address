"""
Tests for the PRNG module — Xoshiro128** and seeding functions.
"""

from __future__ import annotations

import pytest

from prng import Xoshiro128StarStar, create_prng, hash_string, splitmix32


class TestXoshiro128StarStar:
    """Core PRNG tests."""

    def test_determinism(self):
        """Same seed → identical sequence."""
        a = Xoshiro128StarStar(1, 2, 3, 4)
        b = Xoshiro128StarStar(1, 2, 3, 4)
        seq_a = [a.next() for _ in range(100)]
        seq_b = [b.next() for _ in range(100)]
        assert seq_a == seq_b

    def test_different_seeds_diverge(self):
        """Different seeds → different sequences."""
        a = Xoshiro128StarStar(1, 2, 3, 4)
        b = Xoshiro128StarStar(5, 6, 7, 8)
        assert [a.next() for _ in range(10)] != [b.next() for _ in range(10)]

    def test_output_is_32_bit(self):
        """All outputs should be in [0, 2^32)."""
        prng = Xoshiro128StarStar(42, 123, 456, 789)
        for _ in range(1000):
            val = prng.next()
            assert 0 <= val < 2**32

    def test_next_float_range(self):
        """next_float() should return values in [0, 1)."""
        prng = Xoshiro128StarStar(100, 200, 300, 400)
        for _ in range(1000):
            f = prng.next_float()
            assert 0.0 <= f < 1.0

    def test_clone_independence(self):
        """Cloned PRNG should produce same sequence but be independent."""
        original = Xoshiro128StarStar(10, 20, 30, 40)
        # Advance original a few steps.
        for _ in range(5):
            original.next()

        clone = original.clone()

        # Both should produce the same sequence from this point.
        assert [original.next() for _ in range(10)] == [clone.next() for _ in range(10)]

    def test_period_not_trivially_short(self):
        """The PRNG should not cycle within a small number of steps."""
        prng = Xoshiro128StarStar(1, 2, 3, 4)
        initial_state = list(prng.s)
        for i in range(1, 10_001):
            prng.next()
            if list(prng.s) == initial_state:
                pytest.fail(f"PRNG cycled after only {i} steps")

    def test_known_values_seed_1234(self):
        """First 3 values from seed (1,2,3,4) must match cross-language reference."""
        prng = Xoshiro128StarStar(1, 2, 3, 4)
        first3 = [prng.next() for _ in range(3)]
        # These are the reference values matching the Xoshiro128** specification.
        assert first3 == [11520, 0, 5927040]


class TestHashString:
    """Tests for the string hashing function."""

    def test_determinism(self):
        """Same input → same hash."""
        assert hash_string("hello") == hash_string("hello")

    def test_different_strings_diverge(self):
        """Different strings should (almost certainly) produce different hashes."""
        h1 = hash_string("hello")
        h2 = hash_string("world")
        assert h1 != h2

    def test_output_is_32_bit(self):
        """Hash should be in [0, 2^32)."""
        h = hash_string("test string 12345")
        assert 0 <= h < 2**32

    def test_empty_string(self):
        """Empty string should produce a valid hash (not crash)."""
        h = hash_string("")
        assert isinstance(h, int)
        assert 0 <= h < 2**32


class TestSplitMix32:
    """Tests for the SplitMix32 seed expansion."""

    def test_produces_four_values(self):
        """Should expand a single seed into exactly 4 values."""
        result = splitmix32(42)
        assert len(result) == 4

    def test_all_values_32_bit(self):
        """All expanded values should be 32-bit unsigned."""
        for seed in [0, 1, 2**31, 2**32 - 1]:
            for val in splitmix32(seed):
                assert 0 <= val < 2**32

    def test_determinism(self):
        """Same seed → same expansion."""
        assert splitmix32(12345) == splitmix32(12345)

    def test_different_seeds(self):
        """Different seeds → different expansions."""
        assert splitmix32(1) != splitmix32(2)


class TestCreatePRNG:
    """Tests for domain-isolated PRNG creation."""

    def test_domain_isolation(self):
        """Different origins produce different sequences."""
        a = create_prng("https://tracker.com", "2026-07-14")
        b = create_prng("https://example.com", "2026-07-14")
        assert [a.next() for _ in range(5)] != [b.next() for _ in range(5)]

    def test_salt_rotation(self):
        """Same origin, different days → different sequences."""
        a = create_prng("https://tracker.com", "2026-07-14")
        b = create_prng("https://tracker.com", "2026-07-15")
        assert [a.next() for _ in range(5)] != [b.next() for _ in range(5)]

    def test_reproducibility(self):
        """Same origin + salt → same sequence."""
        a = create_prng("https://example.com", "2026-07-14")
        b = create_prng("https://example.com", "2026-07-14")
        assert [a.next() for _ in range(20)] == [b.next() for _ in range(20)]

    def test_returns_xoshiro_instance(self):
        """create_prng should return a Xoshiro128StarStar instance."""
        prng = create_prng("https://test.com", "2026-01-01")
        assert isinstance(prng, Xoshiro128StarStar)

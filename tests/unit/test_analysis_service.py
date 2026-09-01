"""Tests for attack path analysis service."""

import polars as pl

from src.services.analysis import AttackPathService


class TestAttackPathService:
    """Test AttackPathService."""

    def test_analyze_empty(self) -> None:
        df = pl.DataFrame(schema={"cve_id": pl.Utf8})
        result = AttackPathService.analyze(df)
        assert result.is_empty()

    def test_analyze_no_kill_chain(self) -> None:
        df = pl.DataFrame({"cve_id": ["CVE-2024-0001"]})
        result = AttackPathService.analyze(df)
        assert len(result) == 1

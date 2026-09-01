"""Tests for CVSS-BT loader."""

from pathlib import Path
from unittest.mock import patch

import polars as pl
import pytest
import requests

from src.data.loaders.cvss_bt import CVSSBTLoader, _standardize_cvss_bt


class TestCVSSBTLoader:
    """Test CVSSBTLoader caching and standardization."""

    @pytest.fixture
    def tmp_data_dir(self, tmp_path: Path) -> Path:
        return tmp_path / "data"

    @pytest.fixture
    def loader(self, tmp_data_dir: Path) -> CVSSBTLoader:
        return CVSSBTLoader(tmp_data_dir)

    def test_cache_dir_created(self, loader: CVSSBTLoader) -> None:
        assert (loader.data_dir / "CVSS_BT").exists()

    def test_cache_invalid_when_missing(self, loader: CVSSBTLoader) -> None:
        assert not loader._cache_valid()

    def test_standardize_renames_columns(self) -> None:
        df = pl.DataFrame({"cve": ["CVE-2024-0001"], "base_score": [9.8]})
        result = _standardize_cvss_bt(df)
        assert "cve_id" in result.columns
        assert "cvss_base_score" in result.columns

    def test_standardize_bool_columns(self) -> None:
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-0001"],
                "cisa_kev": [1],
                "exploitdb": [1],
            }
        )
        result = _standardize_cvss_bt(df)
        assert result["is_cisa_kev"].dtype == pl.Boolean
        assert result["has_exploitdb"].dtype == pl.Boolean

    def test_standardize_combined_kev(self) -> None:
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-2024-0001"],
                "is_cisa_kev": [True],
                "is_vulncheck_kev": [False],
            }
        )
        result = _standardize_cvss_bt(df)
        assert "is_kev" in result.columns
        assert result["is_kev"][0] is True

    def test_standardize_combined_kev_cisa_only(self) -> None:
        df = pl.DataFrame({"cve_id": ["CVE-1"], "is_cisa_kev": [True]})
        result = _standardize_cvss_bt(df)
        assert result["is_kev"][0] is True

    def test_standardize_combined_exploit(self) -> None:
        df = pl.DataFrame(
            {
                "cve_id": ["CVE-1"],
                "has_exploitdb": [True],
                "has_metasploit": [False],
            }
        )
        result = _standardize_cvss_bt(df)
        assert "has_public_exploit" in result.columns
        assert result["has_public_exploit"][0] is True

    def test_download_returns_none_on_failure(self, loader: CVSSBTLoader) -> None:
        with patch.object(
            requests, "get", side_effect=requests.RequestException("404")
        ):
            result = loader.download(force=True)
            assert result is None

    def test_load_returns_empty_on_failure(self, loader: CVSSBTLoader) -> None:
        with patch.object(loader, "download", return_value=None):
            df = loader.load()
            assert df.is_empty()
            assert "cve_id" in df.columns

    def test_load_standardizes_schema(
        self, loader: CVSSBTLoader, tmp_data_dir: Path
    ) -> None:
        csv_path = loader._cache_path()
        csv_path.write_text("cve,base_score\nCVE-2024-0001,9.8\n")
        df = loader.load()
        assert "cve_id" in df.columns
        assert "cvss_base_score" in df.columns
        assert len(df) == 1

    def test_cache_valid_prevents_redownload(
        self, loader: CVSSBTLoader, tmp_data_dir: Path
    ) -> None:
        csv_path = loader._cache_path()
        csv_path.write_text("data")
        assert loader._cache_valid()

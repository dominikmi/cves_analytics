"""Tests for EPSS loader."""

from pathlib import Path
from unittest.mock import patch

import pytest

from src.data.loaders.epss import EPSSLoader


class TestEPSSLoader:
    """Test EPSSLoader caching and loading."""

    @pytest.fixture
    def loader(self, tmp_path: Path) -> EPSSLoader:
        return EPSSLoader(tmp_path)

    def test_data_dir_created(self, loader: EPSSLoader) -> None:
        assert loader.data_dir.exists()

    def test_load_returns_empty_schema_on_no_data(self, loader: EPSSLoader) -> None:
        with patch.object(loader, "download", return_value=None):
            df = loader.load(date="2024-01-01")
            assert df.is_empty()
            assert "cve" in df.columns

    def test_file_path_generates_correct_paths(self, loader: EPSSLoader) -> None:
        gz, csv = loader._file_path("2024-01-15")
        assert gz.name == "epss_scores-2024-01-15.csv.gz"
        assert csv.name == "epss_scores-2024-01-15.csv"

    def test_download_returns_cached_csv(self, loader: EPSSLoader) -> None:
        csv_path = loader.data_dir / "epss_scores-2024-01-01.csv"
        csv_path.write_text("cve,epss\nCVE-2024-0001,0.5\n")
        result = loader.download(date="2024-01-01")
        assert result == csv_path

    def test_load_reads_csv(self, loader: EPSSLoader) -> None:
        csv_path = loader.data_dir / "epss_scores-2024-01-01.csv"
        csv_path.write_text(
            "# metadata\ncve,epss\nCVE-2024-0001,0.5\nCVE-2024-0002,0.3\n"
        )
        with patch.object(loader, "download", return_value=csv_path):
            df = loader.load(date="2024-01-01")
            assert len(df) == 2

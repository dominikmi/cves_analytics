"""Tests for KEV loader."""

from pathlib import Path
from unittest.mock import patch

import pytest
import requests

from src.data.loaders.kev import KEVLoader


class TestKEVLoader:
    """Test KEVLoader caching and loading."""

    @pytest.fixture
    def loader(self, tmp_path: Path) -> KEVLoader:
        return KEVLoader(tmp_path)

    def test_data_dir_created(self, loader: KEVLoader) -> None:
        assert loader.data_dir.exists()

    def test_load_from_cache(self, loader: KEVLoader) -> None:
        csv_path = loader.data_dir / "known_exploited_vulnerabilities.csv"
        csv_path.write_text("cve,vuln\nCVE-2024-0001,High\n")
        df = loader.load()
        assert df is not None
        assert len(df) == 1

    def test_load_returns_none_on_download_failure(self, loader: KEVLoader) -> None:
        with patch.object(
            requests, "get", side_effect=requests.RequestException("500")
        ):
            df = loader.load(force_download=True)
            assert df is None

    def test_load_force_download(self, loader: KEVLoader) -> None:
        mock_resp = type(
            "R",
            (),
            {
                "raise_for_status": lambda self: None,
                "content": b"cve\nCVE-2024-0001\n",
            },
        )()
        with patch.object(requests, "get", return_value=mock_resp):
            df = loader.load(force_download=True)
            assert df is not None
            assert len(df) == 1

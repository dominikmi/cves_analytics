"""Tests for CWE loader."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from src.data.loaders.cwe import CWELoader


class TestCWELoader:
    """Test CWELoader caching and API fetching."""

    @pytest.fixture
    def loader(self, tmp_path: Path) -> CWELoader:
        return CWELoader(tmp_path)

    def test_special_ids_return_not_found(self, loader: CWELoader) -> None:
        result = loader.get("not_found")
        assert result["cwe_name"] == "not_found"

    def test_empty_id_returns_not_found(self, loader: CWELoader) -> None:
        result = loader.get("")
        assert result["cwe_name"] == "not_found"

    def test_none_id_returns_not_found(self, loader: CWELoader) -> None:
        result = loader.get(None)  # type: ignore[arg-type]
        assert result["cwe_name"] == "not_found"

    def test_get_from_api_success(self, loader: CWELoader) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "Weaknesses": [
                {
                    "Name": "XSS",
                    "Description": "Cross-site scripting",
                    "CommonConsequences": [
                        {"Impact": ["Confidentiality"], "Scope": ["Extended"]}
                    ],
                }
            ]
        }
        with patch("requests.get", return_value=mock_resp):
            result = loader.get("CWE-79")
        assert result["cwe_name"] == "XSS"
        assert result["cwe_desc"] == "Cross-site scripting"

    def test_get_cached(self, loader: CWELoader) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "Weaknesses": [
                {"Name": "XSS", "Description": "Desc", "CommonConsequences": []}
            ]
        }
        with patch("requests.get", return_value=mock_resp):
            loader.get("CWE-79")
        # Second call should hit cache
        with patch("requests.get", side_effect=Exception("should not be called")):
            result = loader.get("CWE-79")
        assert result["cwe_name"] == "XSS"

    def test_get_api_failure_returns_not_found(self, loader: CWELoader) -> None:
        with patch("requests.get", side_effect=Exception("timeout")):
            result = loader.get("CWE-999")
        assert result["cwe_name"] == "not_found"

    def test_get_not_found_string_from_api(self, loader: CWELoader) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = "not found"
        with patch("requests.get", return_value=mock_resp):
            result = loader.get("CWE-000")
        assert result["cwe_name"] == "not_found"

    @pytest.mark.asyncio
    async def test_get_async_success(self, loader: CWELoader) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        mock_resp.json = AsyncMock(
            return_value={
                "Weaknesses": [
                    {
                        "Name": "SQLi",
                        "Description": "SQL injection",
                        "CommonConsequences": [],
                    }
                ]
            }
        )
        mock_session = AsyncMock(spec=aiohttp.ClientSession)
        mock_session.get.return_value = mock_resp

        result = await loader.get_async("CWE-89", mock_session)
        assert result["cwe_name"] == "SQLi"

    @pytest.mark.asyncio
    async def test_batch_get(self, loader: CWELoader) -> None:
        loader._cache = {"CWE-1": {"cwe_id": "CWE-1", "cwe_name": "Cached"}}
        loader._loaded = True
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=None)
        mock_resp.json = AsyncMock(
            return_value={
                "Weaknesses": [
                    {"Name": "New", "Description": "D", "CommonConsequences": []}
                ]
            }
        )
        mock_session = AsyncMock(spec=aiohttp.ClientSession)
        mock_session.get.return_value = mock_resp

        with patch.object(
            loader,
            "get_async",
            new=AsyncMock(
                side_effect=[
                    {"cwe_id": "CWE-2", "cwe_name": "New"},
                ]
            ),
        ):
            result = await loader.batch_get(["CWE-1", "CWE-2"])

        assert result["CWE-1"]["cwe_name"] == "Cached"
        assert result["CWE-2"]["cwe_name"] == "New"

    def test_cache_persisted_to_disk(self, loader: CWELoader) -> None:
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "Weaknesses": [
                {"Name": "XSS", "Description": "D", "CommonConsequences": []}
            ]
        }
        with patch("requests.get", return_value=mock_resp):
            loader.get("CWE-79")
        assert loader._cache_file.exists()

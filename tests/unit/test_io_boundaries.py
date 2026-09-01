"""Tests for I/O boundary code: subprocess execution and network downloads.

Covers the download/decompress/error-fallback bodies of the reference data
loaders and the scanner's subprocess invocation, with ``requests``/``aiohttp``/
``subprocess`` stubbed so the suite stays hermetic.
"""

import gzip
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import polars as pl
import pytest

from src.data.loaders.cvss_bt import CVSSBTLoader
from src.data.loaders.cwe import CWELoader
from src.data.loaders.epss import EPSSLoader
from src.services.scanner import DockerScanner


def _gz_bytes(payload: bytes) -> bytes:
    return gzip.compress(payload)


class _FakeAiohttpResp:
    def __init__(self, payload: bytes, raise_exc: Exception | None = None) -> None:
        self._payload = payload
        self._raise_exc = raise_exc

    def raise_for_status(self) -> None:
        if self._raise_exc is not None:
            raise self._raise_exc

    async def read(self) -> bytes:
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._payload

    async def json(self) -> Any:
        if self._raise_exc is not None:
            raise self._raise_exc
        import json

        return json.loads(self._payload)


class _FakeAiohttpGet:
    def __init__(self, resp: _FakeAiohttpResp) -> None:
        self._resp = resp

    async def __aenter__(self) -> _FakeAiohttpResp:
        return self._resp

    async def __aexit__(self, *exc: object) -> bool:
        return False


class _FakeAiohttpSession:
    def __init__(self, resp: _FakeAiohttpResp) -> None:
        self._resp = resp

    def get(self, url: str, **kwargs: Any) -> _FakeAiohttpGet:
        return _FakeAiohttpGet(self._resp)


class _FakeClientSessionFactory:
    """Stands in for aiohttp.ClientSession.

    The loaders call ``aiohttp.ClientSession()`` and then use the result as
    an async context manager, so this object must be both callable (returning
    itself) and an async CM (yielding the fake session).
    """

    def __init__(self, resp: _FakeAiohttpResp) -> None:
        self._resp = resp

    def __call__(self) -> "_FakeClientSessionFactory":
        return self

    async def __aenter__(self) -> _FakeAiohttpSession:
        return _FakeAiohttpSession(self._resp)

    async def __aexit__(self, *exc: object) -> bool:
        return False


# ---------------------------------------------------------------------------
# Scanner subprocess boundary
# ---------------------------------------------------------------------------


class TestScannerSubprocess:
    def _patch_run(
        self,
        monkeypatch: pytest.MonkeyPatch,
        stdout: bytes = b"{}",
        returncode: int = 0,
    ) -> list[tuple[list[str], dict]]:
        calls: list[tuple[list[str], dict]] = []

        def fake_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
            calls.append((cmd, kwargs))
            return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=b"err")

        monkeypatch.setattr("src.services.scanner.subprocess.run", fake_run)
        return calls

    def test_scan_success_grype(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import json as _json

        payload = _json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {"id": "CVE-2024-0001", "severity": "HIGH"},
                        "artifact": {"name": "libssl", "version": "3.0.0"},
                    }
                ]
            }
        ).encode()

        calls = self._patch_run(monkeypatch, stdout=payload)
        df = DockerScanner("grype").scan("nginx:alpine")

        assert len(df) == 1
        assert df["cve_id"][0] == "CVE-2024-0001"
        assert df["image"][0] == "nginx:alpine"  # image column stamped
        assert calls[0][0] == ["grype", "nginx:alpine", "-o", "json"]

    def test_scan_trivy_uses_format_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = self._patch_run(monkeypatch, stdout=b"{}")
        DockerScanner("trivy").scan("nginx:alpine")
        assert calls[0][0] == ["trivy", "nginx:alpine", "--format", "json"]

    def test_scan_nonzero_returncode_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        self._patch_run(monkeypatch, returncode=1)
        df = DockerScanner("grype").scan("nginx:alpine")
        assert df.is_empty()

    def test_scan_timeout_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import subprocess

        def raising_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=300)

        monkeypatch.setattr("src.services.scanner.subprocess.run", raising_run)
        df = DockerScanner("grype").scan("nginx:alpine")
        assert df.is_empty()

    def test_scan_missing_binary_returns_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def raising_run(cmd: list[str], **kwargs: Any) -> SimpleNamespace:
            raise FileNotFoundError("grype not installed")

        monkeypatch.setattr("src.services.scanner.subprocess.run", raising_run)
        df = DockerScanner("grype").scan("nginx:alpine")
        assert df.is_empty()


# ---------------------------------------------------------------------------
# CVSS-BT download boundary
# ---------------------------------------------------------------------------


class TestCVSSBTDownload:
    def _patch_get(
        self, monkeypatch: pytest.MonkeyPatch, text: str = "", fail: bool = False
    ) -> list[str]:
        calls: list[str] = []

        def fake_get(url: str, timeout: int | None = None) -> SimpleNamespace:
            calls.append(url)
            if fail:
                import requests

                raise requests.RequestException("offline")
            return SimpleNamespace(
                text=text, content=b"", raise_for_status=lambda: None
            )

        monkeypatch.setattr("src.data.loaders.cvss_bt.requests.get", fake_get)
        return calls

    def test_download_success_writes_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loader = CVSSBTLoader(str(tmp_path))
        calls = self._patch_get(monkeypatch, text="cve,base_score\nCVE-1,7.5\n")

        result = loader.download(force=True)
        assert result == loader._cache_path()
        assert result is not None and result.read_text().startswith("cve,")
        assert len(calls) == 1

    def test_stale_cache_fallback_on_download_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os

        loader = CVSSBTLoader(str(tmp_path))
        cache = loader._cache_path()
        cache.write_text("stale\n")
        # age the cache beyond the 1-day TTL
        old = os.times().elapsed - 2 * 86400
        os.utime(cache, (old, old))

        calls = self._patch_get(monkeypatch, fail=True)
        result = loader.download()
        assert result == cache  # fell back to stale cache
        assert len(calls) == 1

    def test_load_parses_cached_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loader = CVSSBTLoader(str(tmp_path))
        cache = loader._cache_path()
        cache.write_text("cve,base_score,base_severity\nCVE-1,7.5,HIGH\n")
        # fresh mtime -> cache valid, no download attempted
        calls = self._patch_get(monkeypatch)

        df = loader.load()
        assert len(df) == 1
        assert df["cvss_base_score"][0] == 7.5
        assert calls == []

    def test_load_unparseable_cache_returns_empty_schema(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loader = CVSSBTLoader(str(tmp_path))
        # row has more fields than the header -> polars raises on read
        loader._cache_path().write_bytes(b"cve,base_score\n1.0,2.0,3.0\n")
        self._patch_get(monkeypatch)  # must not be called (cache is fresh)

        df = loader.load()
        assert df.is_empty()
        assert "cvss_bt_score" in df.columns


# ---------------------------------------------------------------------------
# EPSS download boundary (sync + async)
# ---------------------------------------------------------------------------

EPSS_PAYLOAD = b"#model_version:v1\ncve,epss,percentile\nCVE-1,0.5,0.9\n"


class TestEPSSDownload:
    def _patch_requests(
        self, monkeypatch: pytest.MonkeyPatch, fail: bool = False
    ) -> list[str]:
        calls: list[str] = []

        def fake_get(url: str, timeout: int | None = None) -> SimpleNamespace:
            calls.append(url)
            if fail:
                import requests

                raise requests.RequestException("offline")
            return SimpleNamespace(
                content=_gz_bytes(EPSS_PAYLOAD), raise_for_status=lambda: None
            )

        monkeypatch.setattr("src.data.loaders.epss.requests.get", fake_get)
        return calls

    def test_download_success_writes_and_decompresses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loader = EPSSLoader(str(tmp_path))
        calls = self._patch_requests(monkeypatch)

        result = loader.download(date="2026-08-09")
        assert result is not None and result.exists()
        assert len(calls) == 1

        df = pl.read_csv(result, skip_rows=1)
        assert df["cve"][0] == "CVE-1"

    def test_download_existing_gz_skips_network(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loader = EPSSLoader(str(tmp_path))
        gz, _ = loader._file_path("2026-08-09")
        gz.write_bytes(_gz_bytes(EPSS_PAYLOAD))

        calls = self._patch_requests(monkeypatch)
        result = loader.download(date="2026-08-09")
        assert result is not None and result.exists()
        assert calls == []  # decompressed locally, no download

    def test_download_failure_without_cache_returns_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loader = EPSSLoader(str(tmp_path))
        self._patch_requests(monkeypatch, fail=True)
        assert loader.download(date="2026-08-09") is None

    def test_download_failure_falls_back_to_stale_csv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loader = EPSSLoader(str(tmp_path))
        _, csv = loader._file_path("2026-08-09")
        csv.write_bytes(EPSS_PAYLOAD)

        self._patch_requests(monkeypatch, fail=True)
        assert loader.download(date="2026-08-09") == csv

    def test_load_unparseable_file_returns_empty_schema(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loader = EPSSLoader(str(tmp_path))
        _, csv = loader._file_path("2026-08-09")
        # skip_rows=1 drops the comment line; the row then has more fields
        # than the 3-column header -> polars raises. csv exists, so
        # download() returns it without touching the network.
        csv.write_bytes(b"#model_version:v1\ncve,epss,percentile\nCVE-1,0.5,0.9,extra")

        df = loader.load(date="2026-08-09")
        assert df.is_empty()
        assert "epss" in df.columns

    def test_download_async_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        loader = EPSSLoader(str(tmp_path))
        factory = _FakeClientSessionFactory(_FakeAiohttpResp(_gz_bytes(EPSS_PAYLOAD)))
        monkeypatch.setattr("src.data.loaders.epss.aiohttp.ClientSession", factory)

        result = asyncio.run(loader.download_async(date="2026-08-09"))
        assert result is not None and result.exists()

    def test_download_async_failure_returns_stale_or_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        loader = EPSSLoader(str(tmp_path))
        _, csv = loader._file_path("2026-08-09")
        csv.write_bytes(EPSS_PAYLOAD)  # stale cache for fallback

        factory = _FakeClientSessionFactory(
            _FakeAiohttpResp(b"", raise_exc=RuntimeError("boom"))
        )
        monkeypatch.setattr("src.data.loaders.epss.aiohttp.ClientSession", factory)

        assert asyncio.run(loader.download_async(date="2026-08-09")) == csv


# ---------------------------------------------------------------------------
# CWE fetch boundary (sync + async)
# ---------------------------------------------------------------------------


class _FakeCweResp:
    def __init__(self, data: Any, raise_exc: Exception | None = None) -> None:
        self._data = data
        self._raise_exc = raise_exc

    def raise_for_status(self) -> None:
        if self._raise_exc is not None:
            raise self._raise_exc

    def json(self) -> Any:
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._data


WEAKNESS_PAYLOAD = {
    "Weaknesses": [
        {
            "Name": "Cross-site Scripting",
            "Description": "XSS desc",
            "CommonConsequences": [
                {"Impact": ["Modifies DOM"], "Scope": ["Confidentiality"]}
            ],
        }
    ]
}


class TestCweFetch:
    def test_corrupt_cache_file_is_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        loader = CWELoader(str(tmp_path))
        loader._cache_file.write_text("{not valid json")

        def fake_get(url: str, timeout: int | None = None) -> _FakeCweResp:
            return _FakeCweResp(WEAKNESS_PAYLOAD)

        monkeypatch.setattr("src.data.loaders.cwe.requests.get", fake_get)
        result = loader.get("CWE-79")
        assert result["cwe_name"] == "Cross-site Scripting"

    def test_persist_failure_is_swallowed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Make the cache directory uncreatable: its parent is a regular file.
        blocker = tmp_path / "blocker"
        blocker.write_text("file")
        loader = CWELoader(str(tmp_path))
        loader._cache_file = blocker / "CWE_baseline.json"

        def fake_get(url: str, timeout: int | None = None) -> _FakeCweResp:
            return _FakeCweResp(WEAKNESS_PAYLOAD)

        monkeypatch.setattr("src.data.loaders.cwe.requests.get", fake_get)
        result = loader.get("CWE-79")  # persist raises internally, must not propagate
        assert result["cwe_name"] == "Cross-site Scripting"

    def test_parse_weakness_empty_list(self, tmp_path: Path) -> None:
        loader = CWELoader(str(tmp_path))
        result = loader._parse_weakness("CWE-1", {"Weaknesses": []})
        assert result["cwe_name"] == "not_found"

    def test_parse_weakness_missing_consequences(self, tmp_path: Path) -> None:
        loader = CWELoader(str(tmp_path))
        result = loader._parse_weakness(
            "CWE-2", {"Weaknesses": [{"Name": "N", "Description": "D"}]}
        )
        assert result["cwe_cc_scope"] == "not_found"
        assert result["cwe_cc_impact"] == "not_found"

    def test_get_async_success(self, tmp_path: Path) -> None:
        import asyncio

        loader = CWELoader(str(tmp_path))

        async def run() -> dict[str, Any]:
            session = _FakeAiohttpSession(
                _FakeAiohttpResp(_json_dumps(WEAKNESS_PAYLOAD))  # type: ignore[arg-type]
            )
            return await loader.get_async("CWE-79", session)  # type: ignore[arg-type]

        result = asyncio.run(run())
        assert result["cwe_name"] == "Cross-site Scripting"

    def test_get_async_failure_returns_not_found(self, tmp_path: Path) -> None:
        import asyncio

        loader = CWELoader(str(tmp_path))

        async def run() -> dict[str, Any]:
            session = _FakeAiohttpSession(
                _FakeAiohttpResp(b"", raise_exc=RuntimeError("boom"))  # type: ignore[arg-type]
            )
            return await loader.get_async("CWE-79", session)  # type: ignore[arg-type]

        result = asyncio.run(run())
        assert result["cwe_name"] == "not_found"

    def test_batch_get_mixes_cache_and_fetch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        loader = CWELoader(str(tmp_path))
        # pre-cache one id so only the other hits the (fake) network
        loader._loaded = True
        loader._cache["CWE-1"] = {
            "cwe_id": "CWE-1",
            "cwe_name": "Cached One",
            "cwe_desc": "d",
            "cwe_cc_scope": "s",
            "cwe_cc_impact": "i",
        }

        async def fake_get_async(
            self: CWELoader, cid: str, sess: Any
        ) -> dict[str, Any]:
            return {
                "cwe_id": cid,
                "cwe_name": "Fetched",
                "cwe_desc": "d",
                "cwe_cc_scope": "s",
                "cwe_cc_impact": "i",
            }

        monkeypatch.setattr(CWELoader, "get_async", fake_get_async)

        result = asyncio.run(loader.batch_get(["CWE-1", "CWE-2"]))
        assert result["CWE-1"]["cwe_name"] == "Cached One"
        assert result["CWE-2"]["cwe_name"] == "Fetched"


def _json_dumps(payload: Any) -> bytes:
    import json

    return json.dumps(payload).encode()

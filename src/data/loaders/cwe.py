"""CWE (Common Weakness Enumeration) metadata loader.

Fetches CWE details from MITRE API with disk-backed caching to avoid
repeated calls.
"""

import asyncio
import json
from pathlib import Path
from typing import Any

import aiohttp
import requests

from src.utils.logging_config import get_logger

logger = get_logger(__name__)

CWE_API_URL = "https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_number}"
SPECIAL_CWE_IDS = {"not_found", "NVD-CWE-noinfo", "NVD-CWE-Other"}


class CWELoader:
    """CWE metadata loader with persistent JSON cache.

    Args:
        data_dir: Directory for the cache file.
    """

    def __init__(self, data_dir: str | Path) -> None:
        self._cache_file = Path(data_dir) / "CWE_baseline.json"
        self._cache: dict[str, dict[str, Any]] = {}
        self._loaded = False

    def _ensure_cache(self) -> None:
        if self._loaded:
            return
        if self._cache_file.exists():
            try:
                self._cache = json.loads(self._cache_file.read_text())
            except Exception as exc:
                logger.error("Failed to load CWE cache: %s", exc)
                self._cache = {}
        self._loaded = True

    def _persist_cache(self) -> None:
        try:
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            self._cache_file.write_text(json.dumps(self._cache, indent=2))
        except Exception as exc:
            logger.error("Failed to save CWE cache: %s", exc)

    def _not_found(self, cwe_id: str) -> dict[str, Any]:
        return {
            "cwe_id": cwe_id,
            "cwe_name": "not_found",
            "cwe_desc": "not_found",
            "cwe_cc_scope": "not_found",
            "cwe_cc_impact": "not_found",
        }

    def _parse_weakness(self, cwe_id: str, data: dict[str, Any]) -> dict[str, Any]:
        weaknesses = data.get("Weaknesses", [])
        if not weaknesses:
            return self._not_found(cwe_id)

        w = weaknesses[0]
        consequences = w.get("CommonConsequences", [])
        if consequences:
            conc = consequences[0]
            impact = ", ".join(conc.get("Impact", []) or []) or "not_found"
            scope = ", ".join(conc.get("Scope", []) or []) or "not_found"
        else:
            impact = "not_found"
            scope = "not_found"

        return {
            "cwe_id": cwe_id,
            "cwe_name": w.get("Name", "not_found"),
            "cwe_desc": w.get("Description", "not_found"),
            "cwe_cc_scope": scope,
            "cwe_cc_impact": impact,
        }

    def get(self, cwe_id: str) -> dict[str, Any]:
        """Fetch CWE metadata, using cache when available.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-79").

        Returns:
            Dictionary with CWE metadata fields.
        """
        if not cwe_id or cwe_id in SPECIAL_CWE_IDS:
            return self._not_found(str(cwe_id) if cwe_id else "nan")

        cwe_id = str(cwe_id).strip()
        self._ensure_cache()

        if cwe_id in self._cache:
            return self._cache[cwe_id]

        try:
            number = cwe_id.split("-", 1)[1]
            resp = requests.get(CWE_API_URL.format(cwe_number=number), timeout=30)
            resp.raise_for_status()
            data = resp.json()

            if isinstance(data, str) and "not found" in data:
                result = self._not_found(cwe_id)
            else:
                result = self._parse_weakness(cwe_id, data)

            self._cache[cwe_id] = result
            self._persist_cache()
            return result
        except Exception as exc:
            logger.error("CWE fetch failed for %s: %s", cwe_id, exc)
            result = self._not_found(cwe_id)
            self._cache[cwe_id] = result
            self._persist_cache()
            return result

    async def get_async(
        self, cwe_id: str, session: aiohttp.ClientSession
    ) -> dict[str, Any]:
        """Async version of get.

        Args:
            cwe_id: CWE identifier.
            session: Reusable aiohttp session.

        Returns:
            Dictionary with CWE metadata fields.
        """
        if not cwe_id or cwe_id in SPECIAL_CWE_IDS:
            return self._not_found(str(cwe_id) if cwe_id else "nan")

        cwe_id = str(cwe_id).strip()
        self._ensure_cache()

        if cwe_id in self._cache:
            return self._cache[cwe_id]

        try:
            number = cwe_id.split("-", 1)[1]
            url = CWE_API_URL.format(cwe_number=number)
            async with session.get(url, timeout=aiohttp.ClientTimeout(30)) as resp:
                resp.raise_for_status()
                data = await resp.json()

            if isinstance(data, str) and "not found" in data:
                result = self._not_found(cwe_id)
            else:
                result = self._parse_weakness(cwe_id, data)

            self._cache[cwe_id] = result
            self._persist_cache()
            return result
        except Exception as exc:
            logger.error("CWE async fetch failed for %s: %s", cwe_id, exc)
            result = self._not_found(cwe_id)
            self._cache[cwe_id] = result
            self._persist_cache()
            return result

    async def batch_get(self, cwe_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Fetch multiple CWEs concurrently.

        Args:
            cwe_ids: List of CWE identifiers.

        Returns:
            Mapping from CWE ID to metadata dict.
        """
        self._ensure_cache()
        to_fetch = [cid for cid in cwe_ids if cid not in self._cache]

        if to_fetch:
            async with aiohttp.ClientSession() as session:
                tasks = [self.get_async(cid, session) for cid in to_fetch]
                results = await asyncio.gather(*tasks)
            for result in results:
                self._cache[result["cwe_id"]] = result
            self._persist_cache()

        return {cid: self._cache.get(cid, {}) for cid in cwe_ids}

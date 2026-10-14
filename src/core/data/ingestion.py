# src/core/data/ingestion.py

"""
Data ingestion and validation logic for CVE and asset data.
"""

import asyncio
from pathlib import Path

import aiohttp
import polars as pl
from pydantic import BaseModel

from src.utils.config import get_config


class DataIngestor:
    """Handles data ingestion and validation for CVE and asset data."""

    @staticmethod
    async def download_file(url: str, file_path: Path) -> None:
        """
        Downloads a file from a URL asynchronously.

        Args:
            url: URL to download from.
            file_path: Path to save the downloaded file.

        Raises:
            aiohttp.ClientError: If the download fails.
        """
        async with aiohttp.ClientSession() as session, session.get(url) as response:
            response.raise_for_status()
            with open(file_path, "wb") as f:
                while chunk := await response.content.read(1024):
                    f.write(chunk)

    @staticmethod
    async def download_cve_files(output_dir: Path) -> list[Path]:
        """
        Downloads CVE files from GitHub asynchronously.

        Args:
            output_dir: Directory to save downloaded files.

        Returns:
            List[Path]: List of paths to downloaded files.
        """
        config = get_config()
        cve_url = config.github_cve_url
        max_files = config.github_max_cve_files

        # Placeholder for actual file list retrieval logic.
        # In a real implementation, this would fetch the list of files from GitHub.
        file_urls = [f"{cve_url}example_{i}.json" for i in range(max_files)]

        output_dir.mkdir(parents=True, exist_ok=True)
        tasks = []
        for i, url in enumerate(file_urls):
            file_path = output_dir / f"cve_{i}.json"
            tasks.append(DataIngestor.download_file(url, file_path))

        await asyncio.gather(*tasks)
        return [output_dir / f"cve_{i}.json" for i in range(max_files)]

    @staticmethod
    def load_json_files(json_files: list[Path]) -> pl.DataFrame:
        """
        Loads JSON files into a Polars DataFrame.

        Args:
            json_files: List of paths to JSON files.

        Returns:
            pl.DataFrame: Polars DataFrame containing the loaded data.
        """
        if not json_files:
            return pl.DataFrame()

        return pl.concat([pl.read_json(file) for file in json_files])

    @staticmethod
    def validate_data(df: pl.DataFrame, schema: type[BaseModel]) -> pl.DataFrame:
        """
        Validates a Polars DataFrame against a Pydantic schema.

        Args:
            df: Polars DataFrame to validate.
            schema: Pydantic schema to validate against.

        Returns:
            pl.DataFrame: Validated DataFrame.

        Raises:
            ValidationError: If data does not conform to the schema.
        """
        # Convert Polars DataFrame to a list of dictionaries
        records = df.to_dicts()

        # Validate each record against the Pydantic schema
        validated_records = [schema(**record).model_dump() for record in records]

        # Convert back to Polars DataFrame
        return pl.DataFrame(validated_records)

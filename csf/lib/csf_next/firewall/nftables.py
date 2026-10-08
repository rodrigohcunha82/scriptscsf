"""
CSF Next - native nftables backend.

This module owns only the configured CSF Next table.

IMPORTANT:
- Never flush the global nftables ruleset.
- Never modify third-party tables/chains.
- No packet filtering chains are created at this stage.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
from pathlib import Path
from typing import Any


class NFTablesError(RuntimeError):
    """Base error for nftables operations."""


class NFTables:
    VERSION = "0.2.0"

    VALID_FAMILIES = {"inet", "ip", "ip6"}

    SETS = {
        (4, False): "block4",
        (6, False): "block6",
        (4, True): "temp_block4",
        (6, True): "temp_block6",
    }

    def __init__(
        self,
        *,
        nft: str | Path = "/usr/sbin/nft",
        family: str = "inet",
        table: str = "csf_next",
    ):
        self.nft = Path(nft)
        self.family = family
        self.table = table

        if not self.nft.is_file() or not os.access(self.nft, os.X_OK):
            raise NFTablesError(
                f"nft executable not found: {self.nft}"
            )

        if family not in self.VALID_FAMILIES:
            raise NFTablesError(
                f"Unsupported nftables family: {family}"
            )

        if not table.replace("_", "").isalnum():
            raise NFTablesError(
                f"Invalid nftables table name: {table}"
            )

    # ---------------------------------------------------------
    # Command execution
    # ---------------------------------------------------------

    def _run(
        self,
        *args: str,
        input_text: str | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [str(self.nft), *args],
            input=input_text,
            text=True,
            capture_output=True,
            check=False,
        )

        if check and result.returncode != 0:
            error = (
                result.stderr.strip()
                or result.stdout.strip()
                or "unknown nftables error"
            )

            raise NFTablesError(
                f"nft {' '.join(args)} failed: {error}"
            )

        return result

    # ---------------------------------------------------------
    # Validation
    # ---------------------------------------------------------

    @staticmethod
    def normalize_address(address: str) -> tuple[str, int]:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise NFTablesError(
                f"Invalid IP address: {address}"
            ) from exc

        return str(ip), ip.version

    def _set_for(
        self,
        address: str,
        temporary: bool,
    ) -> tuple[str, str]:
        normalized, version = self.normalize_address(address)

        return normalized, self.SETS[(version, temporary)]

    # ---------------------------------------------------------
    # Table lifecycle
    # ---------------------------------------------------------

    def table_exists(self) -> bool:
        result = self._run(
            "list",
            "table",
            self.family,
            self.table,
            check=False,
        )

        return result.returncode == 0

    def initialize(self) -> None:
        if self.table_exists():
            return

        script = f"""
add table {self.family} {self.table}

add set {self.family} {self.table} block4 {{
    type ipv4_addr
}}

add set {self.family} {self.table} block6 {{
    type ipv6_addr
}}

add set {self.family} {self.table} temp_block4 {{
    type ipv4_addr
    flags timeout
}}

add set {self.family} {self.table} temp_block6 {{
    type ipv6_addr
    flags timeout
}}
"""

        self._run(
            "-f",
            "-",
            input_text=script,
        )

    def delete_table(self) -> None:
        if not self.table_exists():
            return

        self._run(
            "delete",
            "table",
            self.family,
            self.table,
        )

    # ---------------------------------------------------------
    # Elements
    # ---------------------------------------------------------

    def add_permanent(self, address: str) -> None:
        normalized, set_name = self._set_for(
            address,
            temporary=False,
        )

        self._run(
            "add",
            "element",
            self.family,
            self.table,
            set_name,
            f"{{ {normalized} }}",
        )

    def add_temporary(
        self,
        address: str,
        seconds: int,
    ) -> None:
        if (
            not isinstance(seconds, int)
            or isinstance(seconds, bool)
            or seconds <= 0
        ):
            raise NFTablesError(
                "Timeout must be a positive integer"
            )

        normalized, set_name = self._set_for(
            address,
            temporary=True,
        )

        self._run(
            "add",
            "element",
            self.family,
            self.table,
            set_name,
            f"{{ {normalized} timeout {seconds}s }}",
        )

    def remove_permanent(self, address: str) -> None:
        normalized, set_name = self._set_for(
            address,
            temporary=False,
        )

        self._run(
            "delete",
            "element",
            self.family,
            self.table,
            set_name,
            f"{{ {normalized} }}",
        )

    def remove_temporary(self, address: str) -> None:
        normalized, set_name = self._set_for(
            address,
            temporary=True,
        )

        self._run(
            "delete",
            "element",
            self.family,
            self.table,
            set_name,
            f"{{ {normalized} }}",
        )

    # ---------------------------------------------------------
    # Query
    # ---------------------------------------------------------

    def _set_json(self, set_name: str) -> dict[str, Any]:
        if set_name not in set(self.SETS.values()):
            raise NFTablesError(
                f"Invalid CSF Next set: {set_name}"
            )

        result = self._run(
            "-j",
            "list",
            "set",
            self.family,
            self.table,
            set_name,
        )

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise NFTablesError(
                f"Invalid JSON returned by nft for {set_name}"
            ) from exc

        if not isinstance(data, dict):
            raise NFTablesError(
                f"Unexpected JSON structure returned by nft for {set_name}"
            )

        return data

    @staticmethod
    def _extract_elements(data: Any) -> list[str]:
        """
        Extract IP address values from nftables JSON.

        nftables may represent elements in multiple forms.

        Permanent set example:

            "elem": [
                "198.51.100.77"
            ]

        Timeout-enabled sets may contain dictionaries carrying
        element values and timeout metadata.

        The parser intentionally walks the structure recursively
        so it remains compatible with nft JSON schema variations.
        """

        found: list[str] = []

        if isinstance(data, str):
            try:
                ip = ipaddress.ip_address(data)
            except ValueError:
                return found

            found.append(str(ip))
            return found

        if isinstance(data, list):
            for item in data:
                found.extend(
                    NFTables._extract_elements(item)
                )

            return found

        if isinstance(data, dict):
            if "val" in data:
                value = data["val"]

                if isinstance(value, str):
                    try:
                        ip = ipaddress.ip_address(value)
                    except ValueError:
                        pass
                    else:
                        found.append(str(ip))

            if "elem" in data:
                found.extend(
                    NFTables._extract_elements(
                        data["elem"]
                    )
                )

            for key, value in data.items():
                if key in {"val", "elem"}:
                    continue

                found.extend(
                    NFTables._extract_elements(value)
                )

        return found

    def set_contains(
        self,
        set_name: str,
        address: str,
    ) -> bool:
        normalized, _ = self.normalize_address(address)

        data = self._set_json(set_name)

        elements = self._extract_elements(data)

        return normalized in elements

    def contains_permanent(self, address: str) -> bool:
        normalized, set_name = self._set_for(
            address,
            temporary=False,
        )

        return self.set_contains(
            set_name,
            normalized,
        )

    def contains_temporary(self, address: str) -> bool:
        normalized, set_name = self._set_for(
            address,
            temporary=True,
        )

        return self.set_contains(
            set_name,
            normalized,
        )

    def list_table(self) -> str:
        result = self._run(
            "list",
            "table",
            self.family,
            self.table,
        )

        return result.stdout

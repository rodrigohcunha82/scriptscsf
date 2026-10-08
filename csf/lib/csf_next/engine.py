"""
CSF Next - enforcement engine.

Coordinates persistent state in SQLite with runtime enforcement
in nftables.

An nft command returning success is not enough to consider a
block applied. CSF Next verifies the resulting kernel state
before changing kernel_state to "applied".
"""

from __future__ import annotations

import time
from typing import Any, Optional

from csf_next.database import Database
from csf_next.firewall.nftables import NFTables


class EngineError(RuntimeError):
    """Base error for CSF Next engine operations."""


class Engine:
    VERSION = "0.2.0"

    def __init__(
        self,
        database: Database,
        firewall: NFTables,
    ):
        self.database = database
        self.firewall = firewall

    def initialize(self) -> None:
        """
        Ensure the CSF Next-owned nftables structure exists.
        """
        self.firewall.initialize()

    def _mark_error(
        self,
        block_id: int,
        error: str,
    ) -> None:
        self.database.set_kernel_state(
            block_id,
            "error",
            source="engine",
            error=error,
        )

    def block_permanent(
        self,
        address: str,
        *,
        source: str,
        reason: Optional[str] = None,
        service: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> int:
        block_id = self.database.create_block(
            address=address,
            block_type="permanent",
            source=source,
            reason=reason,
            service=service,
            metadata=metadata,
        )

        block = self.database.get_block(block_id)

        if block is None:
            raise EngineError(
                f"Block disappeared after creation: {block_id}"
            )

        normalized_address = str(block["address"])

        try:
            self.firewall.add_permanent(
                normalized_address
            )

            if not self.firewall.contains_permanent(
                normalized_address
            ):
                raise EngineError(
                    "Kernel verification failed after "
                    f"applying permanent block {normalized_address}"
                )

        except Exception as exc:
            self._mark_error(
                block_id,
                str(exc),
            )

            raise EngineError(
                f"Unable to apply permanent block "
                f"{normalized_address}: {exc}"
            ) from exc

        self.database.set_kernel_state(
            block_id,
            "applied",
            source="engine",
        )

        return block_id

    def block_temporary(
        self,
        address: str,
        seconds: int,
        *,
        source: str,
        reason: Optional[str] = None,
        service: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> int:
        if (
            not isinstance(seconds, int)
            or isinstance(seconds, bool)
            or seconds <= 0
        ):
            raise EngineError(
                "seconds must be a positive integer"
            )

        expires_at = int(time.time()) + seconds

        block_id = self.database.create_block(
            address=address,
            block_type="temporary",
            source=source,
            reason=reason,
            service=service,
            expires_at=expires_at,
            metadata=metadata,
        )

        block = self.database.get_block(block_id)

        if block is None:
            raise EngineError(
                f"Block disappeared after creation: {block_id}"
            )

        normalized_address = str(block["address"])

        remaining = (
            int(block["expires_at"])
            - int(time.time())
        )

        if remaining <= 0:
            error = (
                "Temporary block expired before kernel application"
            )

            self._mark_error(
                block_id,
                error,
            )

            raise EngineError(error)

        try:
            self.firewall.add_temporary(
                normalized_address,
                remaining,
            )

            if not self.firewall.contains_temporary(
                normalized_address
            ):
                raise EngineError(
                    "Kernel verification failed after "
                    f"applying temporary block {normalized_address}"
                )

        except Exception as exc:
            self._mark_error(
                block_id,
                str(exc),
            )

            raise EngineError(
                f"Unable to apply temporary block "
                f"{normalized_address}: {exc}"
            ) from exc

        self.database.set_kernel_state(
            block_id,
            "applied",
            source="engine",
        )

        return block_id

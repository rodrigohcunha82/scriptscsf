"""
CSF Next - state reconciler.

Audits and repairs divergence between persistent state stored
in SQLite and runtime state enforced by nftables.

Safety principles:
- Never flush the global nftables ruleset.
- Never modify tables not owned by CSF Next.
- Never delete persistent intent because kernel enforcement failed.
- Verify kernel state after every enforcement operation.
- Record detected drift before attempting automatic recovery.
"""

from __future__ import annotations

import time
from typing import Any

from csf_next.database import Database
from csf_next.firewall.nftables import NFTables


class ReconcilerError(RuntimeError):
    """Base error for CSF Next reconciliation operations."""


class Reconciler:
    VERSION = "0.4.0"

    def __init__(
        self,
        database: Database,
        firewall: NFTables,
    ):
        self.database = database
        self.firewall = firewall

    def _active_blocks(self) -> list[dict[str, Any]]:
        return self.database.active_blocks()

    def _mark_missing(
        self,
        block_id: int,
        *,
        address: str,
        block_type: str,
    ) -> None:
        self.database.set_kernel_state(
            block_id,
            "missing",
            source="reconciler",
            error=(
                f"Active {block_type} block {address} "
                "was not present in nftables"
            ),
        )

    def _reconcile_permanent(
        self,
        block: dict[str, Any],
    ) -> str:
        block_id = int(block["id"])
        address = str(block["address"])
        kernel_state = str(block["kernel_state"])

        present = self.firewall.contains_permanent(
            address
        )

        if present:
            if kernel_state != "applied":
                self.database.set_kernel_state(
                    block_id,
                    "applied",
                    source="reconciler",
                )

                return "applied"

            return "unchanged"

        if kernel_state != "missing":
            self._mark_missing(
                block_id,
                address=address,
                block_type="permanent",
            )

        self.firewall.add_permanent(
            address
        )

        if not self.firewall.contains_permanent(
            address
        ):
            raise ReconcilerError(
                "Kernel verification failed after "
                f"reapplying permanent block {address}"
            )

        self.database.set_kernel_state(
            block_id,
            "applied",
            source="reconciler",
        )

        return "applied"

    def _reconcile_temporary(
        self,
        block: dict[str, Any],
        now: int,
    ) -> str:
        block_id = int(block["id"])
        address = str(block["address"])
        kernel_state = str(block["kernel_state"])

        expires_at = block["expires_at"]

        if expires_at is None:
            raise ReconcilerError(
                f"Temporary block {block_id} has no expires_at"
            )

        remaining = int(expires_at) - now

        if remaining <= 0:
            self.database.mark_expired(
                block_id,
                source="reconciler",
                reason="Temporary block expired",
            )

            return "expired"

        present = self.firewall.contains_temporary(
            address
        )

        if present:
            if kernel_state != "applied":
                self.database.set_kernel_state(
                    block_id,
                    "applied",
                    source="reconciler",
                )

                return "applied"

            return "unchanged"

        if kernel_state != "missing":
            self._mark_missing(
                block_id,
                address=address,
                block_type="temporary",
            )

        self.firewall.add_temporary(
            address,
            remaining,
        )

        if not self.firewall.contains_temporary(
            address
        ):
            raise ReconcilerError(
                "Kernel verification failed after "
                f"reapplying temporary block {address}"
            )

        self.database.set_kernel_state(
            block_id,
            "applied",
            source="reconciler",
        )

        return "applied"

    def reconcile(self) -> dict[str, int]:
        stats = {
            "candidates": 0,
            "unchanged": 0,
            "applied": 0,
            "expired": 0,
            "failed": 0,
        }

        blocks = self._active_blocks()

        stats["candidates"] = len(blocks)

        if not blocks:
            return stats

        try:
            self.firewall.initialize()

        except Exception as exc:
            raise ReconcilerError(
                f"Unable to initialize nftables backend: {exc}"
            ) from exc

        for block in blocks:
            block_id = int(block["id"])
            block_type = str(block["block_type"])

            try:
                if block_type == "permanent":
                    result = self._reconcile_permanent(
                        block
                    )

                elif block_type == "temporary":
                    result = self._reconcile_temporary(
                        block,
                        int(time.time()),
                    )

                else:
                    raise ReconcilerError(
                        f"Unsupported block type: {block_type}"
                    )

                stats[result] += 1

            except Exception as exc:
                try:
                    self.database.set_kernel_state(
                        block_id,
                        "error",
                        source="reconciler",
                        error=str(exc),
                    )
                finally:
                    stats["failed"] += 1

        return stats

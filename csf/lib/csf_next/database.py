"""
CSF Next - SQLite persistence layer.

SQLite is the persistent source of state/history.
nftables remains the runtime enforcement layer.

A database failure must never cause firewall rules to be flushed.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional


class DatabaseError(RuntimeError):
    """Base error for CSF Next database operations."""


class Database:
    VERSION = "0.3.0"

    VALID_KERNEL_STATES = {
        "pending",
        "applied",
        "missing",
        "error",
        "removed",
    }

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self._connection: Optional[sqlite3.Connection] = None

    # ---------------------------------------------------------
    # Connection
    # ---------------------------------------------------------

    def connect(self) -> sqlite3.Connection:
        if self._connection is not None:
            return self._connection

        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )

        connection = sqlite3.connect(
            str(self.db_path),
            timeout=5.0,
            isolation_level=None,
        )

        connection.row_factory = sqlite3.Row

        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 5000")

        foreign_keys = connection.execute(
            "PRAGMA foreign_keys"
        ).fetchone()[0]

        if foreign_keys != 1:
            connection.close()
            raise DatabaseError(
                "SQLite foreign key enforcement could not be enabled"
            )

        journal_mode = connection.execute(
            "PRAGMA journal_mode"
        ).fetchone()[0]

        if str(journal_mode).lower() != "wal":
            connection.close()
            raise DatabaseError(
                f"SQLite WAL mode could not be enabled: {journal_mode}"
            )

        self._connection = connection
        return connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "Database":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    # ---------------------------------------------------------
    # Database health
    # ---------------------------------------------------------

    def integrity_check(self) -> bool:
        row = self.connect().execute(
            "PRAGMA integrity_check"
        ).fetchone()

        return bool(
            row
            and str(row[0]).lower() == "ok"
        )

    def foreign_keys_enabled(self) -> bool:
        row = self.connect().execute(
            "PRAGMA foreign_keys"
        ).fetchone()

        return bool(
            row
            and row[0] == 1
        )

    def journal_mode(self) -> str:
        row = self.connect().execute(
            "PRAGMA journal_mode"
        ).fetchone()

        if not row:
            raise DatabaseError(
                "Unable to determine SQLite journal mode"
            )

        return str(row[0])

    def schema_version(self) -> Optional[int]:
        try:
            row = self.connect().execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()

        except sqlite3.Error as exc:
            raise DatabaseError(
                f"Unable to read schema version: {exc}"
            ) from exc

        if not row or row[0] is None:
            return None

        return int(row[0])

    # ---------------------------------------------------------
    # Address handling
    # ---------------------------------------------------------

    @staticmethod
    def normalize_address(
        address: str,
    ) -> tuple[str, int]:
        try:
            ip = ipaddress.ip_address(address)

        except ValueError as exc:
            raise DatabaseError(
                f"Invalid IP address: {address}"
            ) from exc

        return str(ip), ip.version

    def get_or_create_address(
        self,
        address: str,
        *,
        connection: Optional[sqlite3.Connection] = None,
    ) -> int:
        normalized, family = self.normalize_address(address)

        conn = connection or self.connect()
        now = int(time.time())

        row = conn.execute(
            """
            SELECT id
              FROM addresses
             WHERE address = ?
               AND family = ?
            """,
            (
                normalized,
                family,
            ),
        ).fetchone()

        if row:
            address_id = int(row["id"])

            conn.execute(
                """
                UPDATE addresses
                   SET last_seen = ?
                 WHERE id = ?
                """,
                (
                    now,
                    address_id,
                ),
            )

            return address_id

        cursor = conn.execute(
            """
            INSERT INTO addresses (
                address,
                family,
                first_seen,
                last_seen
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                normalized,
                family,
                now,
                now,
            ),
        )

        return int(cursor.lastrowid)

    # ---------------------------------------------------------
    # Event handling
    # ---------------------------------------------------------

    def add_event(
        self,
        *,
        event_type: str,
        source: str,
        address_id: Optional[int] = None,
        block_id: Optional[int] = None,
        service: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        connection: Optional[sqlite3.Connection] = None,
    ) -> int:
        if not event_type:
            raise DatabaseError(
                "event_type is required"
            )

        if not source:
            raise DatabaseError(
                "source is required"
            )

        metadata_json = None

        if metadata is not None:
            try:
                metadata_json = json.dumps(
                    metadata,
                    separators=(",", ":"),
                    sort_keys=True,
                )

            except (TypeError, ValueError) as exc:
                raise DatabaseError(
                    f"Unable to encode event metadata: {exc}"
                ) from exc

        conn = connection or self.connect()
        now = int(time.time())

        cursor = conn.execute(
            """
            INSERT INTO events (
                address_id,
                block_id,
                event_type,
                source,
                service,
                occurred_at,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                address_id,
                block_id,
                event_type,
                source,
                service,
                now,
                metadata_json,
            ),
        )

        return int(cursor.lastrowid)

    # ---------------------------------------------------------
    # Block handling
    # ---------------------------------------------------------

    def create_block(
        self,
        *,
        address: str,
        block_type: str,
        source: str,
        reason: Optional[str] = None,
        service: Optional[str] = None,
        expires_at: Optional[int] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> int:
        if block_type not in {
            "temporary",
            "permanent",
        }:
            raise DatabaseError(
                "block_type must be temporary or permanent"
            )

        if not source:
            raise DatabaseError(
                "Source is required"
            )

        now = int(time.time())

        if block_type == "temporary":
            if expires_at is None:
                raise DatabaseError(
                    "expires_at is required for temporary blocks"
                )

            if (
                not isinstance(expires_at, int)
                or isinstance(expires_at, bool)
            ):
                raise DatabaseError(
                    "expires_at must be a Unix epoch integer"
                )

            if expires_at <= now:
                raise DatabaseError(
                    "expires_at must be in the future"
                )

        elif expires_at is not None:
            raise DatabaseError(
                "Permanent blocks cannot have expires_at"
            )

        conn = self.connect()

        try:
            conn.execute("BEGIN IMMEDIATE")

            address_id = self.get_or_create_address(
                address,
                connection=conn,
            )

            cursor = conn.execute(
                """
                INSERT INTO blocks (
                    address_id,
                    block_type,
                    source,
                    reason,
                    service,
                    created_at,
                    expires_at,
                    status,
                    kernel_state
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?,
                    'active',
                    'pending'
                )
                """,
                (
                    address_id,
                    block_type,
                    source,
                    reason,
                    service,
                    now,
                    expires_at,
                ),
            )

            block_id = int(cursor.lastrowid)

            self.add_event(
                address_id=address_id,
                block_id=block_id,
                event_type="block_created",
                source=source,
                service=service,
                metadata=metadata,
                connection=conn,
            )

            conn.execute("COMMIT")

            return block_id

        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass

            raise

    def set_kernel_state(
        self,
        block_id: int,
        state: str,
        *,
        source: str = "engine",
        error: Optional[str] = None,
    ) -> None:
        if state not in self.VALID_KERNEL_STATES:
            raise DatabaseError(
                f"Invalid kernel state: {state}"
            )

        if not source:
            raise DatabaseError(
                "source is required"
            )

        conn = self.connect()

        row = conn.execute(
            """
            SELECT
                b.id,
                b.address_id,
                b.service,
                b.kernel_state
            FROM blocks b
            WHERE b.id = ?
            """,
            (block_id,),
        ).fetchone()

        if row is None:
            raise DatabaseError(
                f"Block not found: {block_id}"
            )

        old_state = str(
            row["kernel_state"]
        )

        metadata: dict[str, Any] = {
            "old_state": old_state,
            "new_state": state,
        }

        if error is not None:
            metadata["error"] = str(error)

        try:
            conn.execute("BEGIN IMMEDIATE")

            conn.execute(
                """
                UPDATE blocks
                   SET kernel_state = ?
                 WHERE id = ?
                """,
                (
                    state,
                    block_id,
                ),
            )

            self.add_event(
                address_id=int(
                    row["address_id"]
                ),
                block_id=block_id,
                event_type=f"kernel_{state}",
                source=source,
                service=row["service"],
                metadata=metadata,
                connection=conn,
            )

            conn.execute("COMMIT")

        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass

            raise

    def mark_expired(
        self,
        block_id: int,
        *,
        source: str = "reconciler",
        reason: str = "Temporary block expired",
    ) -> None:
        if not source:
            raise DatabaseError(
                "source is required"
            )

        conn = self.connect()

        row = conn.execute(
            """
            SELECT
                b.id,
                b.address_id,
                b.block_type,
                b.service,
                b.status,
                b.kernel_state
            FROM blocks b
            WHERE b.id = ?
            """,
            (block_id,),
        ).fetchone()

        if row is None:
            raise DatabaseError(
                f"Block not found: {block_id}"
            )

        if str(row["block_type"]) != "temporary":
            raise DatabaseError(
                f"Block {block_id} is not temporary"
            )

        old_status = str(row["status"])
        old_kernel_state = str(row["kernel_state"])
        now = int(time.time())

        metadata = {
            "old_status": old_status,
            "new_status": "expired",
            "old_kernel_state": old_kernel_state,
            "new_kernel_state": "removed",
            "reason": reason,
        }

        try:
            conn.execute("BEGIN IMMEDIATE")

            conn.execute(
                """
                UPDATE blocks
                   SET status = 'expired',
                       kernel_state = 'removed',
                       removed_at = ?,
                       removed_reason = ?
                 WHERE id = ?
                """,
                (
                    now,
                    reason,
                    block_id,
                ),
            )

            self.add_event(
                address_id=int(row["address_id"]),
                block_id=block_id,
                event_type="block_expired",
                source=source,
                service=row["service"],
                metadata=metadata,
                connection=conn,
            )

            conn.execute("COMMIT")

        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass

            raise

    def mark_removed(
        self,
        block_id: int,
        *,
        source: str,
        reason: str = "Block removed",
    ) -> None:
        if not source:
            raise DatabaseError(
                "source is required"
            )

        conn = self.connect()

        row = conn.execute(
            """
            SELECT
                b.id,
                b.address_id,
                b.service,
                b.status,
                b.kernel_state
            FROM blocks b
            WHERE b.id = ?
            """,
            (block_id,),
        ).fetchone()

        if row is None:
            raise DatabaseError(
                f"Block not found: {block_id}"
            )

        old_status = str(row["status"])
        old_kernel_state = str(row["kernel_state"])
        now = int(time.time())

        metadata = {
            "old_status": old_status,
            "new_status": "removed",
            "old_kernel_state": old_kernel_state,
            "new_kernel_state": "removed",
            "reason": reason,
        }

        try:
            conn.execute("BEGIN IMMEDIATE")

            conn.execute(
                """
                UPDATE blocks
                   SET status = 'removed',
                       kernel_state = 'removed',
                       removed_at = ?,
                       removed_reason = ?
                 WHERE id = ?
                """,
                (
                    now,
                    reason,
                    block_id,
                ),
            )

            self.add_event(
                address_id=int(row["address_id"]),
                block_id=block_id,
                event_type="block_removed",
                source=source,
                service=row["service"],
                metadata=metadata,
                connection=conn,
            )

            conn.execute("COMMIT")

        except Exception:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass

            raise

    def get_block(
        self,
        block_id: int,
    ) -> Optional[dict[str, Any]]:
        row = self.connect().execute(
            """
            SELECT
                b.id,
                a.address,
                a.family,
                b.block_type,
                b.source,
                b.reason,
                b.service,
                b.created_at,
                b.expires_at,
                b.status,
                b.kernel_state,
                b.removed_at,
                b.removed_reason
            FROM blocks b
            JOIN addresses a
              ON a.id = b.address_id
            WHERE b.id = ?
            """,
            (block_id,),
        ).fetchone()

        if row is None:
            return None

        return dict(row)

    def active_blocks(
        self,
    ) -> list[dict[str, Any]]:
        rows = self.connect().execute(
            """
            SELECT
                b.id,
                a.address,
                a.family,
                b.block_type,
                b.source,
                b.reason,
                b.service,
                b.created_at,
                b.expires_at,
                b.status,
                b.kernel_state,
                b.removed_at,
                b.removed_reason
            FROM blocks b
            JOIN addresses a
              ON a.id = b.address_id
            WHERE b.status = 'active'
            ORDER BY b.id
            """
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

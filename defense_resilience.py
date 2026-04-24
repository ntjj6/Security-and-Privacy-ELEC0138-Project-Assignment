from __future__ import annotations

import threading
from contextlib import contextmanager
from sqlite3 import Connection
from typing import Any, Iterator


class RaceConditionTransferDefense:
    """In-memory account-level guard for concurrent transfer confirmations."""

    def __init__(self) -> None:
        self.account_locks: dict[int, threading.Lock] = {}
        self.active_accounts: set[int] = set()
        self._registry_lock = threading.Lock()

    @contextmanager
    def guard_transfer(self, sender_account_id: int) -> Iterator[dict[str, Any]]:
        lock = self._lock_for_account(sender_account_id)
        acquired = lock.acquire(blocking=False)

        if not acquired:
            yield self._blocked_decision(
                sender_account_id,
                "concurrent_transfer_in_progress",
                {"active_accounts": sorted(self.active_accounts)},
            )
            return

        with self._registry_lock:
            self.active_accounts.add(sender_account_id)

        try:
            yield {
                "allowed": True,
                "decision": "allow",
                "risk_level": "low",
                "reasons": [],
                "signals": {
                    "sender_account_id": sender_account_id,
                    "rule": "single_active_confirm_per_sender",
                },
            }
        finally:
            with self._registry_lock:
                self.active_accounts.discard(sender_account_id)
            lock.release()

    def evaluate_balance(
        self,
        sender_account_id: int,
        latest_balance: float,
        amount: float,
    ) -> dict[str, Any]:
        signals = {
            "sender_account_id": sender_account_id,
            "latest_balance": round(float(latest_balance), 2),
            "amount": round(float(amount), 2),
            "rule": "block_if_latest_balance_insufficient",
        }

        if latest_balance < amount:
            return self._blocked_decision(
                sender_account_id,
                "latest_balance_insufficient",
                signals,
            )

        return {
            "allowed": True,
            "decision": "allow",
            "risk_level": "low",
            "reasons": [],
            "signals": signals,
        }

    def atomic_debit(self, db: Connection, account_id: int, amount: float) -> dict[str, Any]:
        cursor = db.execute(
            """
            UPDATE accounts
            SET balance = balance - ?
            WHERE id = ? AND balance >= ?
            """,
            (amount, account_id, amount),
        )
        debited = cursor.rowcount == 1
        return {
            "debited": debited,
            "decision": "allow" if debited else "block",
            "risk_level": "low" if debited else "high",
            "reasons": [] if debited else ["atomic_debit_condition_failed"],
            "signals": {
                "account_id": account_id,
                "amount": round(float(amount), 2),
                "rows_updated": cursor.rowcount,
                "rule": "conditional_balance_update",
            },
        }

    def _lock_for_account(self, sender_account_id: int) -> threading.Lock:
        with self._registry_lock:
            lock = self.account_locks.get(sender_account_id)
            if lock is None:
                lock = threading.Lock()
                self.account_locks[sender_account_id] = lock
            return lock

    def _blocked_decision(
        self,
        sender_account_id: int,
        reason: str,
        signals: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        merged_signals = {"sender_account_id": sender_account_id}
        if signals:
            merged_signals.update(signals)

        return {
            "allowed": False,
            "decision": "block",
            "risk_level": "high",
            "reasons": [reason],
            "signals": merged_signals,
        }

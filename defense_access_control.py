from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Any, MutableMapping

from werkzeug.security import check_password_hash


CSRF_SESSION_KEY = "csrf_token"


def generate_csrf_token(session_store: MutableMapping[str, Any]) -> str:
    token = session_store.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session_store[CSRF_SESSION_KEY] = token
    return str(token)


def validate_csrf_token(session_store: MutableMapping[str, Any], submitted_token: str | None) -> bool:
    expected_token = session_store.get(CSRF_SESSION_KEY)
    if not expected_token or not submitted_token:
        return False
    return secrets.compare_digest(str(expected_token), str(submitted_token))


class CredentialAttackDefense:
    """In-memory control for credential guessing and post-login risk tracking."""

    def __init__(
        self,
        max_failed_attempts: int = 5,
        failure_window_seconds: int = 300,
        lockout_seconds: int = 600,
        risk_after_failures: int = 3,
        post_login_risk_seconds: int = 300,
    ) -> None:
        self.max_failed_attempts = max_failed_attempts
        self.failure_window = timedelta(seconds=failure_window_seconds)
        self.lockout_period = timedelta(seconds=lockout_seconds)
        self.risk_after_failures = risk_after_failures
        self.post_login_risk_period = timedelta(seconds=post_login_risk_seconds)
        self.failed_attempts: dict[str, list[datetime]] = {}
        self.locked_accounts: dict[str, datetime] = {}
        self.recent_risky_logins: dict[str, datetime] = {}

    def check_login_allowed(self, username: str | None) -> dict[str, Any]:
        username = self.normalize_username(username)
        self._remove_expired_state(username)
        locked_until = self.locked_accounts.get(username)

        if locked_until is None:
            return {
                "allowed": True,
                "reason": "allowed",
                "failed_attempts": len(self._recent_failures(username)),
                "retry_after_seconds": 0,
            }

        return {
            "allowed": False,
            "reason": "account_temporarily_locked",
            "failed_attempts": len(self._recent_failures(username)),
            "retry_after_seconds": self._seconds_until(locked_until),
        }

    def record_login_result(
        self,
        username: str | None,
        success: bool,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        username = self.normalize_username(username)
        self._remove_expired_state(username)

        if success:
            recent_failures = len(self._recent_failures(username))
            risky_until = None
            if recent_failures >= self.risk_after_failures:
                risky_until = datetime.utcnow() + self.post_login_risk_period
                self.recent_risky_logins[username] = risky_until

            self.failed_attempts.pop(username, None)
            self.locked_accounts.pop(username, None)
            return {
                "username": username,
                "success": True,
                "risk_level": "high" if risky_until else "low",
                "reason": "successful_login_after_multiple_failures" if risky_until else "normal_login",
                "failed_attempts_recent_window": recent_failures,
                "risk_expires_in_seconds": self._seconds_until(risky_until) if risky_until else 0,
                "ip_address": ip_address,
            }

        failures = self._recent_failures(username)
        failures.append(datetime.utcnow())
        self.failed_attempts[username] = failures

        locked_until = None
        if len(failures) >= self.max_failed_attempts:
            locked_until = datetime.utcnow() + self.lockout_period
            self.locked_accounts[username] = locked_until

        if len(failures) >= self.risk_after_failures:
            self.recent_risky_logins[username] = datetime.utcnow() + self.post_login_risk_period

        return {
            "username": username,
            "success": False,
            "risk_level": "high" if len(failures) >= self.risk_after_failures else "medium",
            "reason": "account_temporarily_locked" if locked_until else "failed_login_recorded",
            "failed_attempts_recent_window": len(failures),
            "locked": locked_until is not None,
            "retry_after_seconds": self._seconds_until(locked_until) if locked_until else 0,
            "ip_address": ip_address,
        }

    def get_recent_login_risk(self, username: str | None) -> dict[str, Any]:
        username = self.normalize_username(username)
        self._remove_expired_state(username)
        risky_until = self.recent_risky_logins.get(username)

        if risky_until is None:
            return {
                "username": username,
                "risk_level": "low",
                "reason": "no_recent_credential_attack_signal",
                "active": False,
                "expires_in_seconds": 0,
            }

        return {
            "username": username,
            "risk_level": "high",
            "reason": "recent_credential_attack_signal",
            "active": True,
            "expires_in_seconds": self._seconds_until(risky_until),
        }

    def normalize_username(self, username: str | None) -> str:
        return (username or "unknown").strip().lower() or "unknown"

    def _recent_failures(self, username: str) -> list[datetime]:
        now = datetime.utcnow()
        failures = self.failed_attempts.get(username, [])
        recent_failures = [timestamp for timestamp in failures if now - timestamp <= self.failure_window]
        self.failed_attempts[username] = recent_failures
        return recent_failures

    def _remove_expired_state(self, username: str) -> None:
        locked_until = self.locked_accounts.get(username)
        if locked_until is not None and datetime.utcnow() >= locked_until:
            self.locked_accounts.pop(username, None)
            self.failed_attempts.pop(username, None)

        risky_until = self.recent_risky_logins.get(username)
        if risky_until is not None and datetime.utcnow() >= risky_until:
            self.recent_risky_logins.pop(username, None)

    def _seconds_until(self, expires_at: datetime | None) -> int:
        if expires_at is None:
            return 0
        remaining = expires_at - datetime.utcnow()
        return max(0, int(remaining.total_seconds()))


class TransferRiskDefense:
    """In-memory transfer risk control for account-takeover demos."""

    def __init__(
        self,
        high_value_threshold: float = 500.0,
        max_transfers_per_window: int = 2,
        window_seconds: int = 60,
    ) -> None:
        self.high_value_threshold = high_value_threshold
        self.max_transfers_per_window = max_transfers_per_window
        self.window = timedelta(seconds=window_seconds)
        self.completed_transfers: dict[int, list[datetime]] = {}

    def evaluate_transfer(
        self,
        sender_account_id: int,
        receiver_account_id: int,
        amount: float,
        is_new_payee: bool,
        recent_login_risk: dict[str, Any],
    ) -> dict[str, Any]:
        reasons: list[str] = []
        high_value = amount >= self.high_value_threshold
        recent_login_high_risk = bool(recent_login_risk.get("active")) or recent_login_risk.get("risk_level") == "high"
        transfer_rate_limited = self.is_transfer_rate_limited(sender_account_id)

        if recent_login_high_risk and (is_new_payee or high_value or transfer_rate_limited):
            reasons.append("recent_credential_attack_sensitive_transfer")

        if is_new_payee and high_value:
            reasons.append("new_payee_high_value_transfer")

        if transfer_rate_limited:
            reasons.append("too_many_transfers_in_short_time")

        return {
            "allowed": not reasons,
            "decision": "allow" if not reasons else "block",
            "risk_level": self._risk_level(reasons),
            "reasons": reasons,
            "signals": {
                "sender_account_id": sender_account_id,
                "receiver_account_id": receiver_account_id,
                "amount": amount,
                "is_new_payee": is_new_payee,
                "high_value": high_value,
                "recent_login_high_risk": recent_login_high_risk,
                "transfer_rate_limited": transfer_rate_limited,
            },
        }

    def requires_step_up_auth(
        self,
        amount: float,
        is_new_payee: bool,
        recent_login_risk: dict[str, Any],
        transfer_rate_limited: bool,
    ) -> dict[str, Any]:
        reasons: list[str] = []
        recent_login_high_risk = bool(recent_login_risk.get("active")) or recent_login_risk.get("risk_level") == "high"
        high_value = amount >= self.high_value_threshold

        if recent_login_high_risk:
            reasons.append("recent_login_high_risk")
        if is_new_payee:
            reasons.append("new_payee")
        if high_value:
            reasons.append("high_value_transfer")
        if transfer_rate_limited:
            reasons.append("transfer_velocity_risk")

        return {
            "required": bool(reasons),
            "reasons": reasons,
            "risk_level": "high" if reasons else "low",
            "signals": {
                "amount": amount,
                "is_new_payee": is_new_payee,
                "high_value": high_value,
                "recent_login_high_risk": recent_login_high_risk,
                "transfer_rate_limited": transfer_rate_limited,
            },
        }

    def verify_step_up_password(self, submitted_password: str | None, password_hash: str | None) -> bool:
        if not submitted_password or not password_hash:
            return False
        return check_password_hash(password_hash, submitted_password)

    def record_completed_transfer(self, sender_account_id: int) -> None:
        attempts = self._recent_completed_transfers(sender_account_id)
        attempts.append(datetime.utcnow())
        self.completed_transfers[sender_account_id] = attempts

    def is_transfer_rate_limited(self, sender_account_id: int) -> bool:
        return len(self._recent_completed_transfers(sender_account_id)) >= self.max_transfers_per_window

    def _recent_completed_transfers(self, sender_account_id: int) -> list[datetime]:
        now = datetime.utcnow()
        transfers = self.completed_transfers.get(sender_account_id, [])
        recent_transfers = [timestamp for timestamp in transfers if now - timestamp <= self.window]
        self.completed_transfers[sender_account_id] = recent_transfers
        return recent_transfers

    def _risk_level(self, reasons: list[str]) -> str:
        if not reasons:
            return "low"
        if "recent_credential_attack_sensitive_transfer" in reasons:
            return "critical"
        if len(reasons) >= 2:
            return "high"
        return "medium"

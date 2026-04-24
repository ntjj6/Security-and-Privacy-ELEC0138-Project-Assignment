from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Deque


HONEYPOT_PATHS = {"/admin/debug", "/internal/backup", "/api/private/export"}


class DoSRequestDefense:
    """Small in-memory request limiter for the DoS simulation."""

    def __init__(
        self,
        max_requests_per_window: int = 40,
        request_window_seconds: int = 10,
        max_login_attempts_per_window: int = 10,
        login_window_seconds: int = 10,
        max_concurrent_logins_per_ip: int = 3,
        cooldown_seconds: int = 30,
    ) -> None:
        self.max_requests_per_window = max_requests_per_window
        self.request_window = timedelta(seconds=request_window_seconds)
        self.max_login_attempts_per_window = max_login_attempts_per_window
        self.login_window = timedelta(seconds=login_window_seconds)
        self.max_concurrent_logins_per_ip = max_concurrent_logins_per_ip
        self.cooldown = timedelta(seconds=cooldown_seconds)

        self.request_history_by_ip: dict[str, Deque[datetime]] = {}
        self.login_attempts_by_ip: dict[str, Deque[datetime]] = {}
        self.blocked_until_by_ip: dict[str, datetime] = {}
        self.in_flight_logins_by_ip: dict[str, int] = {}
        self._lock = threading.Lock()

    def check_request_allowed(self, ip_address: str | None, path: str, method: str) -> dict[str, Any]:
        ip_address = self.normalize_ip(ip_address)
        method = method.upper()

        if path.startswith("/static/"):
            return self._allowed_decision(ip_address, path, method, login_tracked=False)

        with self._lock:
            now = datetime.utcnow()
            self._remove_expired_state(ip_address, now)

            blocked_until = self.blocked_until_by_ip.get(ip_address)
            if blocked_until is not None:
                return self._blocked_decision(
                    ip_address,
                    path,
                    method,
                    "ip_temporarily_rate_limited",
                    blocked_until,
                )

            request_history = self._recent_history(
                self.request_history_by_ip,
                ip_address,
                self.request_window,
                now,
            )
            if len(request_history) >= self.max_requests_per_window:
                return self._start_cooldown(
                    ip_address,
                    path,
                    method,
                    "too_many_requests_from_ip",
                    now,
                    {
                        "requests_in_window": len(request_history),
                        "limit": self.max_requests_per_window,
                        "window_seconds": int(self.request_window.total_seconds()),
                    },
                )

            is_login_post = path == "/login" and method == "POST"
            if is_login_post:
                in_flight = self.in_flight_logins_by_ip.get(ip_address, 0)
                if in_flight >= self.max_concurrent_logins_per_ip:
                    return self._start_cooldown(
                        ip_address,
                        path,
                        method,
                        "too_many_concurrent_login_attempts",
                        now,
                        {
                            "in_flight_logins": in_flight,
                            "limit": self.max_concurrent_logins_per_ip,
                        },
                    )

                login_history = self._recent_history(
                    self.login_attempts_by_ip,
                    ip_address,
                    self.login_window,
                    now,
                )
                if len(login_history) >= self.max_login_attempts_per_window:
                    return self._start_cooldown(
                        ip_address,
                        path,
                        method,
                        "too_many_login_attempts",
                        now,
                        {
                            "login_attempts_in_window": len(login_history),
                            "limit": self.max_login_attempts_per_window,
                            "window_seconds": int(self.login_window.total_seconds()),
                        },
                    )

                login_history.append(now)
                self.in_flight_logins_by_ip[ip_address] = in_flight + 1

            request_history.append(now)
            return self._allowed_decision(ip_address, path, method, login_tracked=is_login_post)

    def finish_login_request(self, ip_address: str | None) -> None:
        ip_address = self.normalize_ip(ip_address)
        with self._lock:
            in_flight = self.in_flight_logins_by_ip.get(ip_address, 0)
            if in_flight <= 1:
                self.in_flight_logins_by_ip.pop(ip_address, None)
                return
            self.in_flight_logins_by_ip[ip_address] = in_flight - 1

    def detect_honeypot_probe(self, path: str) -> dict[str, Any]:
        normalized_path = path.rstrip("/") or "/"
        matched = normalized_path in HONEYPOT_PATHS
        return {
            "detected": matched,
            "path": normalized_path,
            "reason": "honeypot_probe" if matched else "not_honeypot_path",
        }

    def normalize_ip(self, ip_address: str | None) -> str:
        first_ip = (ip_address or "local").split(",", 1)[0]
        return first_ip.strip() or "local"

    def _recent_history(
        self,
        history_by_ip: dict[str, Deque[datetime]],
        ip_address: str,
        window: timedelta,
        now: datetime,
    ) -> Deque[datetime]:
        history = history_by_ip.setdefault(ip_address, deque())
        while history and now - history[0] > window:
            history.popleft()
        return history

    def _remove_expired_state(self, ip_address: str, now: datetime) -> None:
        blocked_until = self.blocked_until_by_ip.get(ip_address)
        if blocked_until is not None and now >= blocked_until:
            self.blocked_until_by_ip.pop(ip_address, None)

        self._recent_history(self.request_history_by_ip, ip_address, self.request_window, now)
        self._recent_history(self.login_attempts_by_ip, ip_address, self.login_window, now)

    def _start_cooldown(
        self,
        ip_address: str,
        path: str,
        method: str,
        reason: str,
        now: datetime,
        signals: dict[str, Any],
    ) -> dict[str, Any]:
        blocked_until = now + self.cooldown
        self.blocked_until_by_ip[ip_address] = blocked_until
        return self._blocked_decision(ip_address, path, method, reason, blocked_until, signals)

    def _allowed_decision(
        self,
        ip_address: str,
        path: str,
        method: str,
        login_tracked: bool,
    ) -> dict[str, Any]:
        return {
            "allowed": True,
            "decision": "allow",
            "status_code": 200,
            "reason": "allowed",
            "retry_after_seconds": 0,
            "login_tracked": login_tracked,
            "signals": {
                "ip_address": ip_address,
                "path": path,
                "method": method,
            },
        }

    def _blocked_decision(
        self,
        ip_address: str,
        path: str,
        method: str,
        reason: str,
        blocked_until: datetime,
        signals: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        retry_after_seconds = max(1, int((blocked_until - datetime.utcnow()).total_seconds()))
        merged_signals = {
            "ip_address": ip_address,
            "path": path,
            "method": method,
        }
        if signals:
            merged_signals.update(signals)

        return {
            "allowed": False,
            "decision": "block",
            "status_code": 429,
            "reason": reason,
            "retry_after_seconds": retry_after_seconds,
            "login_tracked": False,
            "signals": merged_signals,
        }


class RuleBasedIDS:
    """Small in-memory IDS for login spray and suspicious client signals."""

    def __init__(
        self,
        window_seconds: int = 300,
        login_spray_username_threshold: int = 3,
        suspicious_signal_threshold: int = 3,
        dedupe_seconds: int = 300,
    ) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.login_spray_username_threshold = login_spray_username_threshold
        self.suspicious_signal_threshold = suspicious_signal_threshold
        self.dedupe_period = timedelta(seconds=dedupe_seconds)
        self.login_failures_by_ip: dict[str, Deque[tuple[datetime, str]]] = {}
        self.suspicious_signals_by_ip: dict[str, Deque[tuple[datetime, str]]] = {}
        self.last_alert_by_ip_rule: dict[tuple[str, str], datetime] = {}
        self._lock = threading.Lock()

    def record_login_failure(self, ip_address: str | None, username: str | None) -> dict[str, Any]:
        ip_address = self.normalize_ip(ip_address)
        username = self.normalize_username(username)
        with self._lock:
            now = datetime.utcnow()
            failures = self._recent_login_failures(ip_address, now)
            failures.append((now, username))
            unique_usernames = sorted({name for _, name in failures if name != "unknown"})
            triggered = len(unique_usernames) >= self.login_spray_username_threshold
            return self._decision(
                ip_address=ip_address,
                rule="login_spray_detected",
                triggered=triggered,
                now=now,
                signals={
                    "unique_usernames": unique_usernames,
                    "unique_username_count": len(unique_usernames),
                    "failure_count": len(failures),
                    "window_seconds": int(self.window.total_seconds()),
                },
            )

    def record_suspicious_client_signal(
        self,
        ip_address: str | None,
        signal_type: str,
        path: str | None = None,
        status_code: int | None = None,
    ) -> dict[str, Any]:
        ip_address = self.normalize_ip(ip_address)
        with self._lock:
            now = datetime.utcnow()
            signals = self._recent_suspicious_signals(ip_address, now)
            signals.append((now, signal_type))
            signal_counts: dict[str, int] = {}
            for _, signal in signals:
                signal_counts[signal] = signal_counts.get(signal, 0) + 1
            triggered = len(signals) >= self.suspicious_signal_threshold
            return self._decision(
                ip_address=ip_address,
                rule="suspicious_client_activity",
                triggered=triggered,
                now=now,
                signals={
                    "signal_type": signal_type,
                    "signal_count": len(signals),
                    "signal_counts": signal_counts,
                    "path": path,
                    "status_code": status_code,
                    "window_seconds": int(self.window.total_seconds()),
                },
            )

    def normalize_ip(self, ip_address: str | None) -> str:
        first_ip = (ip_address or "local").split(",", 1)[0]
        return first_ip.strip() or "local"

    def normalize_username(self, username: str | None) -> str:
        return (username or "unknown").strip().lower() or "unknown"

    def _recent_login_failures(self, ip_address: str, now: datetime) -> Deque[tuple[datetime, str]]:
        failures = self.login_failures_by_ip.setdefault(ip_address, deque())
        while failures and now - failures[0][0] > self.window:
            failures.popleft()
        return failures

    def _recent_suspicious_signals(self, ip_address: str, now: datetime) -> Deque[tuple[datetime, str]]:
        signals = self.suspicious_signals_by_ip.setdefault(ip_address, deque())
        while signals and now - signals[0][0] > self.window:
            signals.popleft()
        return signals

    def _decision(
        self,
        ip_address: str,
        rule: str,
        triggered: bool,
        now: datetime,
        signals: dict[str, Any],
    ) -> dict[str, Any]:
        alert_key = (ip_address, rule)
        last_alert = self.last_alert_by_ip_rule.get(alert_key)
        deduped = bool(last_alert and now - last_alert <= self.dedupe_period)
        should_alert = triggered and not deduped
        if should_alert:
            self.last_alert_by_ip_rule[alert_key] = now

        return {
            "triggered": triggered,
            "should_alert": should_alert,
            "deduped": deduped,
            "rule": rule,
            "ip_address": ip_address,
            "severity": "high" if triggered else "low",
            "signals": signals,
        }

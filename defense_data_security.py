from __future__ import annotations

import re
from typing import Any


def mask_account_number(account_number: str | None) -> str:
    if not account_number:
        return "Unavailable"
    tail = str(account_number)[-4:]
    return f"•••• {tail}"


class DataSecurityDefense:
    """Small data minimization helper for display and security logging."""

    _ipv4_pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

    def mask_account_number(self, value: str | None) -> str:
        return mask_account_number(value)

    def mask_ip(self, ip_address: str | None) -> str:
        value = self.redact_text(ip_address, max_length=80)
        if not value:
            return "unknown"

        normalized = value.strip()
        if normalized.lower() in {"local", "unknown", "localhost"}:
            return normalized

        if "," in normalized:
            return ", ".join(self.mask_ip(part.strip()) for part in normalized.split(","))

        match = self._ipv4_pattern.match(normalized)
        if match:
            octets = match.groups()
            return f"{octets[0]}.{octets[1]}.{octets[2]}.xxx"

        return normalized

    def redact_text(self, value: Any, max_length: int = 120) -> str:
        if value is None:
            return ""
        text = str(value).replace("\r", " ").replace("\n", " ")
        text = re.sub(r"\s+", " ", text).strip()
        if max_length > 0 and len(text) > max_length:
            return text[: max_length - 3].rstrip() + "..."
        return text

    def sanitize_security_details(self, details: Any) -> str:
        return self.redact_text(details, max_length=500)

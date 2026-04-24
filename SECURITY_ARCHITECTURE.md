# Security Architecture

## 1. Overview

This project implements a four-layer defensive architecture for the mock banking platform. The controls are designed as application-level security measures for common online banking risks, not as one-off mitigations for the included demonstration scripts.

The current four layers are:

- **Layer 1: Access controls and authentication** in `defense_access_control.py`
- **Layer 2: Data security and privacy** in `defense_data_security.py`
- **Layer 3: Network protection and monitoring** in `defense_network_monitoring.py`
- **Layer 4: Resilience against emerging threats** in `defense_resilience.py`

Some advanced security ideas are implemented as lightweight coursework versions. For example, the project uses rule-based IDS logic instead of AI-based IDS, password re-entry as step-up authentication instead of full MFA/TOTP, and in-memory state instead of a distributed security state store.

## 2. Threat model

The platform assumes an attacker may:

- Attempt credential guessing, password spraying, or account takeover.
- Reuse compromised credentials to initiate fraudulent transfers.
- Abuse high-risk transfer properties such as new payees, high-value amounts, or rapid repeated transfers.
- Send concurrent transfer confirmations to exploit stale balance checks.
- Flood application endpoints to degrade availability.
- Probe sensitive-looking internal routes such as debug, backup, or private export paths.
- Try to inject excessive or multi-line data into logs or dashboard-visible fields.

The platform does not assume the local development host, browser, or database server is fully hostile. The controls are application-level defenses suitable for a mock Flask banking system.

## 3. Layer 1: Access controls and authentication

Layer 1 is implemented mainly in `defense_access_control.py` and integrated through `app.py`.

### Password hashing

User passwords are stored as Werkzeug password hashes. `app.py` uses:

- `generate_password_hash(...)` when seeding demo users.
- `check_password_hash(...)` during login and step-up authentication.

Plaintext passwords are not stored in the database.

### Login lockout

`CredentialAttackDefense` tracks failed login attempts in memory:

- `check_login_allowed(username)` blocks temporarily locked accounts before password verification.
- `record_login_result(username, success, ip_address)` records failed attempts, lockout state, and recent risky login signals.
- `get_recent_login_risk(username)` exposes recent high-risk login state for transfer controls.

This mitigates credential guessing and creates a risk signal for downstream transfer decisions.

### RBAC

Role-based access control is enforced in `app.py`:

- Admin users are redirected to `/admin/security`.
- Customer routes such as dashboard, account, transactions, and transfer reject admin access.
- Admin security pages require `current_user_role(app) == "admin"`.

This is a lightweight RBAC model based on the `users.role` field.

### CSRF

`defense_access_control.py` provides:

- `generate_csrf_token(session_store)`
- `validate_csrf_token(session_store, submitted_token)`

The token is stored in Flask `session["csrf_token"]`. `app.py` injects it into templates and validates it before processing POST requests for `/login` and `/transfer`.

The templates `templates/login.html` and `templates/transfer.html` include hidden `csrf_token` fields.

### Step-up authentication as lightweight MFA / Zero Trust

`TransferRiskDefense` implements simplified step-up authentication:

- `requires_step_up_auth(...)`
- `verify_step_up_password(...)`

When a transfer has elevated risk, the confirm step requires the current user password again. This is a coursework-level Zero Trust or MFA substitute. It is not full MFA, SMS OTP, push approval, or TOTP. It still adds value because a transfer must be freshly authenticated when risk signals are present.

Step-up is required for:

- Recent high-risk login signals.
- New payees.
- High-value transfers.
- Transfer velocity risk.

Step-up does not bypass existing transfer blocking. If `TransferRiskDefense.evaluate_transfer(...)` blocks a transfer, password re-entry does not make that transfer safe.

## 4. Layer 2: Data security and privacy

Layer 2 is implemented in `defense_data_security.py` through `DataSecurityDefense`.

### Masking

`DataSecurityDefense.mask_account_number(value)` masks account numbers for templates.

`DataSecurityDefense.mask_ip(ip_address)` masks IPv4 addresses for display and export. For example:

```text
192.168.1.25 -> 192.168.1.xxx
```

Readable local values such as `local`, `unknown`, and `localhost` are preserved.

### Log minimisation

`DataSecurityDefense.redact_text(value, max_length=120)` removes newlines, compresses whitespace, and truncates long values. This limits log injection and avoids collecting more display text than needed.

CSV export uses `prepare_export_value(...)` in `app.py` to mask IP addresses and redact fields such as `note`, `details`, and `user_agent`.

### Sanitised security events

`record_security_event(...)` in `app.py` calls:

```python
data_security.sanitize_security_details(details)
```

before inserting into `security_events`. This means security event details are normalised and length-limited before storage.

### Field-level encryption

Field-level encryption is not implemented in the current coursework version. In production, sensitive fields such as account metadata, detailed audit logs, and customer identifiers should be encrypted with managed keys, preferably through a KMS-backed envelope encryption design.

## 5. Layer 3: Network protection and monitoring

Layer 3 is implemented in `defense_network_monitoring.py` and integrated through Flask request hooks in `app.py`.

### Rate limiting

`DoSRequestDefense.check_request_allowed(ip_address, path, method)` applies in-memory request limits by IP address. It can return HTTP `429` with retry metadata when an IP exceeds configured thresholds.

This protects application availability during request floods.

### Concurrent login control

`DoSRequestDefense` also tracks concurrent login POST requests by IP:

- `max_concurrent_logins_per_ip`
- `finish_login_request(ip_address)`

`app.py` calls `finish_login_request(...)` during teardown and after-request handling to release in-flight login counters.

### Rule-based IDS

`RuleBasedIDS` is a lightweight, deterministic IDS. It is a coursework-level replacement for more advanced AI IDS approaches.

Implemented rules:

- `record_login_failure(...)` detects login spraying when one IP fails against multiple usernames in a short window.
- `record_suspicious_client_signal(...)` detects repeated suspicious client activity such as repeated `429` responses or honeypot probes.

IDS alerts are deduplicated per IP and rule, then written as:

- `ids_login_spray_detected`
- `ids_suspicious_client_activity`

### Honeypot/deception routes

`DoSRequestDefense.detect_honeypot_probe(path)` detects probes for deceptive sensitive-looking paths:

- `/admin/debug`
- `/internal/backup`
- `/api/private/export`

`app.py` records `honeypot_probe` security events and returns `404 Not Found` so the application does not reveal that the route is a honeypot.

### Security dashboard

The admin dashboard at `/admin/security` displays recent security events, high-risk transfers, suspicious login patterns, request metrics, transfer attempts, and audit data.

It is not itself a SIEM, but it provides a compact monitoring view for the layered controls.

## 6. Layer 4: Resilience against emerging threats

Layer 4 is implemented mainly in `defense_resilience.py`, with some transfer velocity logic in `defense_access_control.py`.

### Transfer lock

`RaceConditionTransferDefense.guard_transfer(sender_account_id)` uses an in-memory per-account lock to prevent two active transfer confirmations for the same sender account in the same process.

This is a local-process concurrency guard.

### Latest balance recheck

`RaceConditionTransferDefense.evaluate_balance(...)` checks the latest account balance immediately before funds movement. This catches stale preview data and blocks transfers when the balance is no longer sufficient.

### Atomic conditional debit

`RaceConditionTransferDefense.atomic_debit(db, account_id, amount)` performs the debit with a database condition:

```sql
UPDATE accounts
SET balance = balance - ?
WHERE id = ? AND balance >= ?
```

`app.py` wraps the debit, receiver credit, and transaction insert in an explicit transaction using `BEGIN IMMEDIATE`. If the conditional debit fails, the receiver is not credited, no completed transaction is written, the attempt is rejected, and a `transfer_atomic_debit_failed` security event is recorded.

This prevents negative balances even if concurrent requests bypass earlier application-level checks.

### Transfer velocity control

`TransferRiskDefense` tracks completed transfers in memory and detects too many transfers in a short window:

- `record_completed_transfer(sender_account_id)`
- `is_transfer_rate_limited(sender_account_id)`

Velocity risk contributes to both transfer blocking and step-up authentication decisions.

## 7. Mapping from original attacks to layered defenses

### Attack 1 credential + transfer abuse

Relevant defenses:

- Password hashing in `app.py`.
- Login lockout in `CredentialAttackDefense`.
- Recent risky login tracking in `CredentialAttackDefense`.
- CSRF validation for login and transfer POSTs.
- Step-up authentication in `TransferRiskDefense`.
- Transfer risk blocking for new payee, high-value amount, recent credential risk, and velocity risk.
- Security event logging and dashboard visibility.
- IDS login spray detection in `RuleBasedIDS`.

The goal is not only to break one scripted attack, but to reduce account takeover and fraudulent transfer risk more generally.

### Attack 2 race condition

Relevant defenses:

- `RaceConditionTransferDefense.guard_transfer(...)` per-account transfer lock.
- `RaceConditionTransferDefense.evaluate_balance(...)` latest balance recheck.
- `RaceConditionTransferDefense.atomic_debit(...)` database-level conditional debit.
- Explicit transaction in `app.py` around debit, credit, and transaction insert.
- Rejected transfer attempts and security events for race or atomic debit failures.

These controls create layered protection: application lock first, latest state check second, and database conditional update as the final authority.

### Attack 3 DoS

Relevant defenses:

- `DoSRequestDefense.check_request_allowed(...)` request rate limiting.
- Login-specific request window controls.
- Concurrent login controls.
- `RuleBasedIDS.record_suspicious_client_signal(...)` for repeated 429 and honeypot signals.
- Request logging and admin dashboard monitoring.

The current version is lightweight and in-memory, but it demonstrates the core behavior expected from network protection and monitoring controls.

## 8. Limitations and production improvements

The current design is intentionally lightweight. Production improvements would include:

- Move in-memory state to Redis, a database, or another shared store so lockout, IDS, rate limits, transfer locks, and velocity controls work across multiple application workers.
- Replace password re-entry with real MFA such as TOTP, WebAuthn, push approval, or phishing-resistant passkeys.
- Enforce HTTPS/TLS end to end, including secure cookies and HSTS.
- Add field-level encryption for sensitive data, backed by a KMS or HSM.
- Put a WAF, reverse proxy, or API gateway in front of the Flask app for network-layer filtering and distributed rate limiting.
- Add centralised logging and alerting through a SIEM.
- Add stronger audit integrity, such as append-only logs or tamper-evident event chains.
- Consider post-quantum cryptography for future key exchange and long-lived confidentiality requirements as standards and platform support mature.

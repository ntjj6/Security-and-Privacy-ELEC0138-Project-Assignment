# Mock Banking Platform Defended

This project is a local coursework demonstration platform built with `Flask + SQLite`. It is designed to show how a digital banking app behaves under attack scenarios, and how defensive controls can detect, block, or log those attacks.

The project combines three parts into one coursework demo:

- `app.py`: the main banking platform, including login, account pages, transfers, auditing, and the security operations dashboard
- `attack_*.py`: attack scripts used to reproduce account takeover, unauthorised transfer abuse, race conditions, and DoS pressure
- `defense_*.py`: defense modules used to implement CSRF protection, credential attack protection, transfer risk controls, DoS mitigation, IDS monitoring, and race-condition protection

## 1. Platform Overview

The main application is [app.py](D:/桌面/security作业/mock_banking_platform_defened/mock_banking_platform_defened/app.py). When started, it provides a local banking web app.

Main routes and functions include:

- `/login`: user login
- `/dashboard`: customer dashboard
- `/account`: account information page
- `/transactions`: transaction history page
- `/transfer`: two-step transfer flow with preview and confirmation
- `/admin/security`: security operations and attack evidence dashboard
- `/admin/security/export/<dataset>`: export security-related CSV datasets
- `/health`: local health check endpoint

The platform automatically initializes the database at `instance/bank.db` and seeds demo data including:

- users and accounts
- transactions
- login logs
- request logs
- transfer attempt records
- balance audit records
- security event records

## 2. Demo Accounts

The application automatically creates the following accounts:

- Standard customer accounts
  - `alice / alice123`
  - `bob / bob123`
  - `carol / carol123`
- Attacker-controlled recipient account
  - `mallory / mallory123`
- Administrator account
  - username: `admin`
  - password: uses the default value in code unless overridden by the `BANK_ADMIN_PASSWORD` environment variable

The account `mallory` is explicitly treated in the code as a risky / attacker-controlled destination for fraud demonstrations.

## 3. Attack Scripts

The project includes three attack scripts, all intended for the local target `http://127.0.0.1:5000`.

### 3.1 Credential Attack + Unauthorised Transfer

File: [attack_1_credential_and_transfer.py](D:/桌面/security作业/mock_banking_platform_defened/mock_banking_platform_defened/attack_1_credential_and_transfer.py)

This script performs a full attack chain:

1. Enumerates likely usernames
2. Tries common weak passwords and username-based password patterns
3. If login succeeds, takes over the victim session
4. Opens the transfer page
5. Sends unauthorised transfers to `mallory`
6. Attempts both a normal-value transfer and a higher-risk transfer

This script is mainly used to demonstrate:

- credential guessing / password spraying
- account takeover
- unauthorised transfer abuse to an attacker-controlled account

Run with:

```powershell
python attack_1_credential_and_transfer.py
```

### 3.2 Race Condition / Double Transfer

File: [attack_2_race_condition.py](D:/桌面/security作业/mock_banking_platform_defened/mock_banking_platform_defened/attack_2_race_condition.py)

This script:

1. Resets the victim and attacker balances
2. Logs in as the victim
3. Prepares two transfer confirmations submitted almost simultaneously
4. Checks whether both succeed against stale balance state

The scripted demo parameters are:

- victim starting balance: `GBP 100.00`
- two concurrent transfer confirmations of: `GBP 80.00`
- without protection, the account may transfer out `GBP 160.00` in total and go negative

Run with:

```powershell
python attack_2_race_condition.py
```

### 3.3 DoS Simulation

File: [attack_3_dos_simulation.py](D:/桌面/security作业/mock_banking_platform_defened/mock_banking_platform_defened/attack_3_dos_simulation.py)

This script sends many concurrent POST requests to `/login` to simulate basic availability pressure.

Default parameters:

- total requests: `300`
- concurrency: `30`

Run with:

```powershell
python attack_3_dos_simulation.py
```

## 4. Defense Modules

### 4.1 Access Control and Transfer Risk Controls

File: [defense_access_control.py](D:/桌面/security作业/mock_banking_platform_defened/mock_banking_platform_defened/defense_access_control.py)

This module implements:

- CSRF token generation and validation
- failed login tracking and temporary lockout
- recent risky-login state tracking
- transfer risk evaluation
- step-up verification for risky transfers
- short-window transfer velocity detection

The logic pays particular attention to signals such as:

- repeated recent failed logins
- new payees
- high-value transfers
- too many transfers in a short time

### 4.2 Data Minimization and Redaction

File: [defense_data_security.py](D:/桌面/security作业/mock_banking_platform_defened/mock_banking_platform_defened/defense_data_security.py)

This module implements:

- account-number masking
- IP address masking
- text redaction and truncation for logs and event details

It is mainly used to reduce unnecessary exposure of sensitive information in the UI and in security logging.

### 4.3 Network Monitoring and IDS

File: [defense_network_monitoring.py](D:/桌面/security作业/mock_banking_platform_defened/mock_banking_platform_defened/defense_network_monitoring.py)

This file provides two main protections:

- `DoSRequestDefense`
  - per-IP request rate limiting
  - login window limiting
  - concurrent login limiting per IP
  - cooldown-based temporary blocking
- `RuleBasedIDS`
  - login spray detection
  - suspicious client activity detection
  - honeypot probe alerting

The code also defines honeypot paths such as:

- `/admin/debug`
- `/internal/backup`
- `/api/private/export`

### 4.4 Concurrent Transfer Protection

File: [defense_resilience.py](D:/桌面/security作业/mock_banking_platform_defened/mock_banking_platform_defened/defense_resilience.py)

This module is specifically designed to handle race-condition transfer problems. It includes:

- only one active transfer confirmation per sender account
- re-checking the latest balance before completing a transfer
- conditional atomic debit logic

This module directly corresponds to the scenario demonstrated by `attack_2_race_condition.py`.

## 5. Defense Switches

This project supports enabling or disabling defenses by module. These switches are defined in [app.py](D:/桌面/security作业/mock_banking_platform_defened/mock_banking_platform_defened/app.py) and read from environment variables.

Available switches:

- `BANK_ENABLE_CSRF_DEFENSE`
- `BANK_ENABLE_CREDENTIAL_DEFENSE`
- `BANK_ENABLE_TRANSFER_DEFENSE`
- `BANK_ENABLE_DOS_DEFENSE`
- `BANK_ENABLE_IDS_DEFENSE`
- `BANK_ENABLE_RACE_DEFENSE`

By default, all of these defenses are enabled.

The code interprets the values as follows:

- environment variable not set: uses the default value `True`
- set to `0`, `false`, `no`, `off`, or an empty value: disabled
- any other value: enabled

For example, to disable race-condition protection and DoS defense:

```powershell
$env:BANK_ENABLE_RACE_DEFENSE="false"
$env:BANK_ENABLE_DOS_DEFENSE="false"
python app.py
```

To disable only transfer risk controls:

```powershell
$env:BANK_ENABLE_TRANSFER_DEFENSE="0"
python app.py
```

This makes it easy to demonstrate before/after comparisons with defenses turned off and then turned on again.

## 6. Security Operations Dashboard

After logging in as an administrator, the `/admin/security` page provides a dashboard for attack evidence and defensive monitoring. It includes:

- failed login counts
- slow request counts
- transfers to `mallory`
- duplicate transfer signals
- recent security events
- potentially risky transfers
- transfer attempt audit data
- balance audit trail
- hot request paths
- suspicious login patterns

The dashboard also supports exporting:

- `request_logs`
- `login_failures`
- `transfer_attempts`
- `balance_audits`

## 7. Setup and Run

Python `3.10+` is recommended.

### Install dependencies

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Start the platform

```powershell
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## 8. Suggested Coursework Demo Flow

A clear demo sequence would be:

1. Start the app and show the normal banking functions with a customer account.
2. Log in to the admin security page and explain the auditing and monitoring features.
3. Disable selected defenses and run the attack scripts to show successful attack behaviour.
4. Re-enable the defenses and run the same scripts again to show blocking or mitigation.
5. Use `/admin/security` to present before/after evidence.

## 9. Notes

- This project is for local coursework and security demonstration only.
- All data is dummy data.
- On first run, the application creates `instance/bank.db` automatically.
- To reset the demo data, delete `instance/bank.db` and start the app again.
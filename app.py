from __future__ import annotations

import csv
import os
import sqlite3
from io import StringIO
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    flash,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from defense_access_control import (
    CredentialAttackDefense,
    TransferRiskDefense,
    generate_csrf_token,
    validate_csrf_token,
)
from defense_data_security import DataSecurityDefense
from defense_network_monitoring import DoSRequestDefense, RuleBasedIDS
from defense_resilience import RaceConditionTransferDefense

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
DATABASE_PATH = INSTANCE_DIR / "bank.db"

RISKY_DESTINATION_USERNAMES = {"mallory"}
HIGH_VALUE_TRANSFER_THRESHOLD = 500.0
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_ENV_VAR = "BANK_ADMIN_PASSWORD"
DEFAULT_ADMIN_PASSWORD = "S3cureAdmin!2026#UCL"
ADMIN_LOCKOUT_THRESHOLD = 3
ADMIN_LOCKOUT_WINDOW_MINUTES = 5


def env_flag(name: str, default: bool = True) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off", ""}


ENABLE_CSRF_DEFENSE = env_flag("BANK_ENABLE_CSRF_DEFENSE", True)
ENABLE_CREDENTIAL_DEFENSE = env_flag("BANK_ENABLE_CREDENTIAL_DEFENSE", True)
ENABLE_TRANSFER_DEFENSE = env_flag("BANK_ENABLE_TRANSFER_DEFENSE", True)
ENABLE_DOS_DEFENSE = env_flag("BANK_ENABLE_DOS_DEFENSE", True)
ENABLE_IDS_DEFENSE = env_flag("BANK_ENABLE_IDS_DEFENSE", True)
ENABLE_RACE_DEFENSE = env_flag("BANK_ENABLE_RACE_DEFENSE", True)

credential_defense = CredentialAttackDefense(
    max_failed_attempts=5, 
    failure_window_seconds=300,
    lockout_seconds=60,
    risk_after_failures=3,
    post_login_risk_seconds=300,
)
transfer_defense = TransferRiskDefense(
    high_value_threshold=HIGH_VALUE_TRANSFER_THRESHOLD,
    max_transfers_per_window=2,
    window_seconds=60,
)
race_condition_defense = RaceConditionTransferDefense()
dos_defense = DoSRequestDefense(
    max_requests_per_window=40,
    request_window_seconds=10,
    max_login_attempts_per_window=10,
    login_window_seconds=10,
    max_concurrent_logins_per_ip=3,
    cooldown_seconds=30,
)
ids_monitor = RuleBasedIDS()
data_security = DataSecurityDefense()

RECENT_TRANSACTION_QUERY = """
SELECT
    t.*,
    sender.full_name AS from_name,
    sender.username AS from_username,
    sender_account.account_number AS from_account_number,
    receiver.full_name AS to_name,
    receiver.username AS to_username,
    receiver_account.account_number AS to_account_number
FROM transactions t
JOIN accounts sender_account ON t.from_account_id = sender_account.id
JOIN users sender ON sender_account.user_id = sender.id
JOIN accounts receiver_account ON t.to_account_id = receiver_account.id
JOIN users receiver ON receiver_account.user_id = receiver.id
WHERE t.from_account_id = ? OR t.to_account_id = ?
ORDER BY t.created_at DESC
"""


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
    app.config["DATABASE"] = str(DATABASE_PATH)

    INSTANCE_DIR.mkdir(exist_ok=True)

    @app.before_request
    def before_request():
        g.request_started_at = datetime.utcnow()
        g.skip_request_log = False
        g.dos_login_ip = None

        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "local")
        if ENABLE_DOS_DEFENSE:
            dos_decision = dos_defense.check_request_allowed(ip_address, request.path, request.method)
        else:
            dos_decision = {
                "allowed": True,
                "decision": "allow",
                "status_code": 200,
                "reason": "dos_defense_disabled",
                "retry_after_seconds": 0,
                "login_tracked": False,
                "signals": {
                    "ip_address": ip_address,
                    "path": request.path,
                    "method": request.method,
                },
            }
        if not dos_decision["allowed"]:
            g.skip_request_log = True
            record_ids_decision(
                app,
                ids_monitor.record_suspicious_client_signal(
                    ip_address,
                    signal_type="http_429",
                    path=request.path,
                    status_code=dos_decision["status_code"],
                ),
            )
            response = make_response("Too many requests. Please retry later.", dos_decision["status_code"])
            response.headers["Retry-After"] = str(dos_decision["retry_after_seconds"])
            response.headers["X-RateLimit-Reason"] = dos_decision["reason"]
            return response

        if dos_decision.get("login_tracked"):
            g.dos_login_ip = dos_decision["signals"]["ip_address"]

        g.db = get_db(app)

        honeypot_decision = (
            dos_defense.detect_honeypot_probe(request.path)
            if ENABLE_DOS_DEFENSE
            else {"detected": False, "path": request.path, "reason": "dos_defense_disabled"}
        )
        if honeypot_decision["detected"]:
            g.skip_request_log = True
            masked_ip = data_security.mask_ip(ip_address)
            safe_path = data_security.redact_text(honeypot_decision["path"], max_length=120)
            record_ids_decision(
                app,
                ids_monitor.record_suspicious_client_signal(
                    ip_address,
                    signal_type="honeypot_probe",
                    path=honeypot_decision["path"],
                    status_code=404,
                ),
            )
            record_security_event(
                app,
                event_type="honeypot_probe",
                severity="high",
                details=f"Honeypot probe path={safe_path}; client_ip={masked_ip}",
            )
            return make_response("Not Found", 404)

    @app.teardown_request
    def teardown_request(exception: BaseException | None) -> None:
        dos_login_ip = getattr(g, "dos_login_ip", None)
        if ENABLE_DOS_DEFENSE and dos_login_ip:
            dos_defense.finish_login_request(dos_login_ip)
            g.dos_login_ip = None

        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.after_request
    def after_request(response):
        dos_login_ip = getattr(g, "dos_login_ip", None)
        if ENABLE_DOS_DEFENSE and dos_login_ip:
            dos_defense.finish_login_request(dos_login_ip)
            g.dos_login_ip = None

        if request.path.startswith("/static/"):
            return response
        if getattr(g, "skip_request_log", False):
            return response
        started_at = getattr(g, "request_started_at", None)
        if started_at is not None:
            duration_ms = int((datetime.utcnow() - started_at).total_seconds() * 1000)
            log_request_event(
                app,
                path=request.path,
                method=request.method,
                status_code=response.status_code,
                duration_ms=duration_ms,
                ip_address=request.headers.get("X-Forwarded-For", request.remote_addr or "local"),
                user_agent=request.headers.get("User-Agent", "unknown")[:255],
                user_id=session.get("user_id"),
            )
        return response

    @app.context_processor
    def inject_user() -> dict[str, Any]:
        user = None
        if session.get("user_id"):
            user = query_one(app, "SELECT * FROM users WHERE id = ?", (session["user_id"],))
        return {"current_user": user, "csrf_token": generate_csrf_token(session)}

    @app.template_filter("mask_account")
    def mask_account_filter(value: str | None) -> str:
        return data_security.mask_account_number(value)

    @app.template_filter("mask_ip")
    def mask_ip_filter(value: str | None) -> str:
        return data_security.mask_ip(value)

    @app.template_filter("redact_text")
    def redact_text_filter(value: Any, max_length: int = 120) -> str:
        return data_security.redact_text(value, max_length=max_length)

    @app.template_filter("currency")
    def currency_filter(value: float | int) -> str:
        return f"£{float(value):,.2f}"

    @app.route("/")
    def index():
        if session.get("user_id"):
            if current_user_role(app) == "admin":
                return redirect(url_for("admin_security"))
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            if ENABLE_CSRF_DEFENSE and not validate_csrf_token(session, request.form.get("csrf_token")):
                flash("Invalid form token. Please try again.", "error")
                return render_template("login.html"), 400

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            ip_address = request.headers.get("X-Forwarded-For", request.remote_addr or "local")

            if ENABLE_CREDENTIAL_DEFENSE:
                login_decision = credential_defense.check_login_allowed(username)
            else:
                login_decision = {
                    "allowed": True,
                    "reason": "credential_defense_disabled",
                    "failed_attempts": 0,
                    "retry_after_seconds": 0,
                }
            if not login_decision["allowed"]:
                log_login_attempt(app, username=username or "unknown", success=False, ip_address=ip_address)
                record_ids_decision(
                    app,
                    ids_monitor.record_login_failure(ip_address, username),
                )
                record_security_event(
                    app,
                    event_type="login_blocked_locked_account",
                    severity="high",
                    username=username or "unknown",
                    details=(
                        f"Credential defense blocked login from {ip_address}; "
                        f"reason: {login_decision['reason']}; "
                        f"recent failures: {login_decision['failed_attempts']}; "
                        f"retry after: {login_decision['retry_after_seconds']} seconds"
                    ),
                )
                flash("Account temporarily locked due to repeated failed login attempts.", "error")
                return (
                    render_template("login.html"),
                    423,
                    {"Retry-After": str(login_decision["retry_after_seconds"])},
                )

            user = query_one(app, "SELECT * FROM users WHERE username = ?", (username,))
            is_admin_user = bool(user and user["role"] == "admin")

            if is_admin_user and is_admin_locked_out(app, username):
                log_login_attempt(app, username=username, success=False, ip_address=ip_address)
                record_ids_decision(
                    app,
                    ids_monitor.record_login_failure(ip_address, username),
                )
                record_security_event(
                    app,
                    event_type="admin_lockout",
                    severity="high",
                    username=username,
                    user_id=user["id"],
                    details=f"Blocked admin login during cooldown window from {ip_address}",
                )
                flash("\u767b\u5f55\u5931\u8d25\u3002", "error")
                return render_template("login.html")

            password_matches = bool(user and check_password_hash(user["password_hash"], password))
            success = bool(user and password_matches)
            log_login_attempt(app, username=username, success=success, ip_address=ip_address)
            if ENABLE_CREDENTIAL_DEFENSE:
                credential_result = credential_defense.record_login_result(
                    username=username,
                    success=success,
                    ip_address=ip_address,
                )
            else:
                credential_result = {
                    "username": username,
                    "success": success,
                    "risk_level": "low",
                    "reason": "credential_defense_disabled",
                    "failed_attempts_recent_window": 0,
                    "risk_expires_in_seconds": 0,
                    "retry_after_seconds": 0,
                    "locked": False,
                    "ip_address": ip_address,
                }

            if success:
                session.clear()
                session["user_id"] = user["id"]
                account_row = query_one(app, "SELECT id FROM accounts WHERE user_id = ?", (user["id"],))
                session["account_id"] = account_row["id"] if account_row else None
                record_security_event(
                    app,
                    event_type="login_success",
                    severity="low",
                    username=username,
                    user_id=user["id"],
                    account_id=session.get("account_id"),
                    details=(
                        f"Successful login from {ip_address}; "
                        f"credential risk: {credential_result['risk_level']}; "
                        f"reason: {credential_result['reason']}"
                    ),
                )
                flash("Logged in successfully.", "success")
                if user["role"] == "admin":
                    return redirect(url_for("admin_security"))
                return redirect(url_for("dashboard"))

            record_security_event(
                app,
                event_type="login_failure",
                severity=credential_result["risk_level"],
                username=username or "unknown",
                details=(
                    f"Failed login attempt from {ip_address}; "
                    f"recent failures: {credential_result['failed_attempts_recent_window']}; "
                    f"reason: {credential_result['reason']}"
                ),
            )
            record_ids_decision(
                app,
                ids_monitor.record_login_failure(ip_address, username),
            )
            if credential_result.get("locked"):
                record_security_event(
                    app,
                    event_type="account_lockout_triggered",
                    severity="high",
                    username=username or "unknown",
                    details=(
                        f"Credential defense locked account after "
                        f"{credential_result['failed_attempts_recent_window']} failures from {ip_address}; "
                        f"retry after: {credential_result['retry_after_seconds']} seconds"
                    ),
                )
                flash("Too many failed login attempts. Account temporarily locked.", "error")
                return (
                    render_template("login.html"),
                    423,
                    {"Retry-After": str(credential_result["retry_after_seconds"])},
                )
            if is_admin_user:
                flash("\u767b\u5f55\u5931\u8d25\u3002", "error")
            elif not user:
                flash("\u7528\u6237\u540d\u4e0d\u6b63\u786e\u3002", "error")
            else:
                flash("\u5bc6\u7801\u4e0d\u6b63\u786e\u3002", "error")

        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        if session.get("user_id"):
            record_security_event(
                app,
                event_type="logout",
                severity="low",
                username=current_username(app),
                user_id=session.get("user_id"),
                account_id=session.get("account_id"),
                details="User logged out",
            )
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        if current_user_role(app) == "admin":
            return redirect(url_for("admin_security"))
        account = get_current_account(app)
        transactions = query_all(app, RECENT_TRANSACTION_QUERY + "LIMIT 5", (account["id"], account["id"]))
        recent_logins = query_all(
            app,
            """
            SELECT attempted_at, success, ip_address
            FROM login_logs
            WHERE username = ?
            ORDER BY attempted_at DESC
            LIMIT 5
            """,
            (current_username(app),),
        )
        recent_security_events = query_all(
            app,
            """
            SELECT event_type, severity, details, created_at
            FROM security_events
            WHERE user_id = ? OR username = ?
            ORDER BY created_at DESC
            LIMIT 6
            """,
            (session["user_id"], current_username(app)),
        )
        return render_template(
            "dashboard.html",
            account=account,
            transactions=transactions,
            recent_logins=recent_logins,
            recent_security_events=recent_security_events,
        )

    @app.route("/account")
    @login_required
    def account_details():
        if current_user_role(app) == "admin":
            return redirect(url_for("admin_security"))
        account = get_current_account(app)
        return render_template("account.html", account=account)

    @app.route("/transactions")
    @login_required
    def transactions_page():
        if current_user_role(app) == "admin":
            return redirect(url_for("admin_security"))
        account = get_current_account(app)
        transactions = query_all(app, RECENT_TRANSACTION_QUERY, (account["id"], account["id"]))
        return render_template("transactions.html", account=account, transactions=transactions)

    @app.route("/transfer", methods=["GET", "POST"])
    @login_required
    def transfer():
        if current_user_role(app) == "admin":
            return redirect(url_for("admin_security"))
        account = get_current_account(app)
        users = query_all(
            app,
            """
            SELECT users.full_name, users.username, accounts.id as account_id, accounts.account_number
            FROM accounts
            JOIN users ON users.id = accounts.user_id
            WHERE accounts.id != ? AND users.role = 'customer'
            ORDER BY CASE WHEN users.username = 'mallory' THEN 0 ELSE 1 END, users.full_name
            """,
            (account["id"],),
        )

        preview = None
        form_data = {"to_account_id": "", "amount": "", "note": ""}

        if request.method == "POST":
            if ENABLE_CSRF_DEFENSE and not validate_csrf_token(session, request.form.get("csrf_token")):
                flash("Invalid form token. Please try again.", "error")
                return (
                    render_template(
                        "transfer.html",
                        account=account,
                        users=users,
                        preview=None,
                        form_data=form_data,
                    ),
                    400,
                )

            action = request.form.get("action", "preview")
            form_data = {
                "to_account_id": request.form.get("to_account_id", "").strip(),
                "amount": request.form.get("amount", "").strip(),
                "note": request.form.get("note", "").strip()[:120],
            }
            attempt_id = log_transfer_attempt(
                app,
                user_id=session["user_id"],
                from_account_id=account["id"],
                to_account_id=int(form_data["to_account_id"]) if form_data["to_account_id"].isdigit() else None,
                amount_text=form_data["amount"],
                action=action,
                status="submitted",
                note=form_data["note"],
            )

            transfer_data = validate_transfer_form(app, account, form_data)
            if transfer_data is None:
                update_transfer_attempt(app, attempt_id, "rejected")
                return render_template(
                    "transfer.html",
                    account=account,
                    users=users,
                    preview=None,
                    form_data=form_data,
                )

            preview = {
                "receiver_name": transfer_data["receiver_name"],
                "receiver_username": transfer_data["receiver_username"],
                "receiver_account_number": transfer_data["receiver_account_number"],
                "amount": transfer_data["amount"],
                "note": transfer_data["note"] or "Transfer",
                "projected_balance": round(account["balance"] - transfer_data["amount"], 2),
                "risk_flags": transfer_data["risk_flags"],
                "risk_level": transfer_data["risk_level"],
            }

            if ENABLE_CREDENTIAL_DEFENSE:
                recent_login_risk = credential_defense.get_recent_login_risk(current_username(app))
            else:
                recent_login_risk = {
                    "username": current_username(app),
                    "risk_level": "low",
                    "reason": "credential_defense_disabled",
                    "active": False,
                    "expires_in_seconds": 0,
                }
            if ENABLE_TRANSFER_DEFENSE:
                transfer_decision = transfer_defense.evaluate_transfer(
                    sender_account_id=account["id"],
                    receiver_account_id=transfer_data["receiver_id"],
                    amount=transfer_data["amount"],
                    is_new_payee="new_payee" in transfer_data["risk_flags"],
                    recent_login_risk=recent_login_risk,
                )
                step_up_decision = transfer_defense.requires_step_up_auth(
                    amount=transfer_data["amount"],
                    is_new_payee="new_payee" in transfer_data["risk_flags"],
                    recent_login_risk=recent_login_risk,
                    transfer_rate_limited=bool(transfer_decision["signals"]["transfer_rate_limited"]),
                )
            else:
                transfer_decision = {
                    "allowed": True,
                    "decision": "allow",
                    "risk_level": "low",
                    "reasons": [],
                    "signals": {
                        "sender_account_id": account["id"],
                        "receiver_account_id": transfer_data["receiver_id"],
                        "amount": transfer_data["amount"],
                        "is_new_payee": "new_payee" in transfer_data["risk_flags"],
                        "high_value": transfer_data["amount"] >= HIGH_VALUE_TRANSFER_THRESHOLD,
                        "recent_login_high_risk": False,
                        "transfer_rate_limited": False,
                    },
                }
                step_up_decision = {
                    "required": False,
                    "reasons": [],
                    "risk_level": "low",
                    "signals": {
                        "amount": transfer_data["amount"],
                        "is_new_payee": "new_payee" in transfer_data["risk_flags"],
                        "high_value": transfer_data["amount"] >= HIGH_VALUE_TRANSFER_THRESHOLD,
                        "recent_login_high_risk": False,
                        "transfer_rate_limited": False,
                    },
                }
            preview["step_up_required"] = step_up_decision["required"]
            preview["step_up_reasons"] = step_up_decision["reasons"]

            if action == "preview":
                update_transfer_attempt(app, attempt_id, "previewed", transfer_data["receiver_id"], transfer_data["amount"])
                record_security_event(
                    app,
                    event_type="transfer_preview",
                    severity=transfer_data["risk_level"],
                    username=current_username(app),
                    user_id=session["user_id"],
                    account_id=account["id"],
                    target_account_id=transfer_data["receiver_id"],
                    details=(
                        f"Previewed transfer of £{transfer_data['amount']:.2f} to "
                        f"{transfer_data['receiver_name']} ({transfer_data['receiver_username']}); "
                        f"flags: {', '.join(transfer_data['risk_flags']) or 'none'}"
                    ),
                )

            if action == "confirm":
                if step_up_decision["required"]:
                    submitted_step_up_password = request.form.get("step_up_password", "")
                    current_user = query_one(app, "SELECT password_hash FROM users WHERE id = ?", (session["user_id"],))
                    step_up_verified = transfer_defense.verify_step_up_password(
                        submitted_step_up_password,
                        current_user["password_hash"] if current_user else None,
                    )
                    if not step_up_verified:
                        update_transfer_attempt(app, attempt_id, "rejected", transfer_data["receiver_id"], transfer_data["amount"])
                        event_type = "step_up_failed" if submitted_step_up_password else "step_up_required"
                        record_security_event(
                            app,
                            event_type=event_type,
                            severity=step_up_decision["risk_level"],
                            username=current_username(app),
                            user_id=session["user_id"],
                            account_id=account["id"],
                            target_account_id=transfer_data["receiver_id"],
                            details=(
                                f"Step-up authentication {'failed' if submitted_step_up_password else 'required'} "
                                f"for transfer of GBP {transfer_data['amount']:.2f} to "
                                f"{transfer_data['receiver_name']} ({transfer_data['receiver_username']}); "
                                f"reasons: {', '.join(step_up_decision['reasons'])}"
                            ),
                        )
                        if submitted_step_up_password:
                            flash("Additional verification failed. Re-enter your current password.", "error")
                        else:
                            flash("Additional verification is required for this transfer.", "error")
                        return (
                            render_template(
                                "transfer.html",
                                account=account,
                                users=users,
                                preview=preview,
                                form_data=form_data,
                            ),
                            403 if submitted_step_up_password else 200,
                        )

                if not transfer_decision["allowed"]:
                    update_transfer_attempt(app, attempt_id, "rejected", transfer_data["receiver_id"], transfer_data["amount"])
                    record_security_event(
                        app,
                        event_type="transfer_blocked",
                        severity=transfer_decision["risk_level"],
                        username=current_username(app),
                        user_id=session["user_id"],
                        account_id=account["id"],
                        target_account_id=transfer_data["receiver_id"],
                        details=(
                            f"Transfer risk defense blocked transfer of GBP {transfer_data['amount']:.2f} to "
                            f"{transfer_data['receiver_name']} ({transfer_data['receiver_username']}); "
                            f"reasons: {', '.join(transfer_decision['reasons'])}; "
                            f"login risk: {recent_login_risk['risk_level']}; "
                            f"flags: {', '.join(transfer_data['risk_flags']) or 'none'}"
                        ),
                    )
                    flash("Transfer blocked by account takeover protection.", "error")
                    return (
                        render_template(
                            "transfer.html",
                            account=account,
                            users=users,
                            preview=preview,
                            form_data=form_data,
                        ),
                        403,
                    )

                db = get_db(app)
                if ENABLE_RACE_DEFENSE:
                    with race_condition_defense.guard_transfer(account["id"]) as race_decision:
                        if not race_decision["allowed"]:
                            update_transfer_attempt(app, attempt_id, "rejected", transfer_data["receiver_id"], transfer_data["amount"])
                            record_security_event(
                                app,
                                event_type="transfer_race_blocked",
                                severity=race_decision["risk_level"],
                                username=current_username(app),
                                user_id=session["user_id"],
                                account_id=account["id"],
                                target_account_id=transfer_data["receiver_id"],
                                details=(
                                    f"Race-condition defense blocked transfer of GBP {transfer_data['amount']:.2f} to "
                                    f"{transfer_data['receiver_name']} ({transfer_data['receiver_username']}); "
                                    f"reasons: {', '.join(race_decision['reasons'])}"
                                ),
                            )
                            flash("Transfer blocked because another confirmation is already in progress.", "error")
                            return (
                                render_template(
                                    "transfer.html",
                                    account=account,
                                    users=users,
                                    preview=preview,
                                    form_data=form_data,
                                ),
                                409,
                            )

                        latest_sender_account = db.execute(
                            "SELECT balance FROM accounts WHERE id = ?",
                            (account["id"],),
                        ).fetchone()
                        balance_before = float(latest_sender_account["balance"]) if latest_sender_account else 0.0
                        balance_decision = race_condition_defense.evaluate_balance(
                            sender_account_id=account["id"],
                            latest_balance=balance_before,
                            amount=transfer_data["amount"],
                        )
                        if not balance_decision["allowed"]:
                            update_transfer_attempt(app, attempt_id, "rejected", transfer_data["receiver_id"], transfer_data["amount"])
                            record_security_event(
                                app,
                                event_type="transfer_race_blocked",
                                severity=balance_decision["risk_level"],
                                username=current_username(app),
                                user_id=session["user_id"],
                                account_id=account["id"],
                                target_account_id=transfer_data["receiver_id"],
                                details=(
                                    f"Race-condition defense blocked transfer of GBP {transfer_data['amount']:.2f} to "
                                    f"{transfer_data['receiver_name']} ({transfer_data['receiver_username']}); "
                                    f"reasons: {', '.join(balance_decision['reasons'])}; "
                                    f"latest balance: GBP {balance_before:.2f}"
                                ),
                            )
                            flash("Transfer blocked because the latest balance is insufficient.", "error")
                            return (
                                render_template(
                                    "transfer.html",
                                    account=account,
                                    users=users,
                                    preview=preview,
                                    form_data=form_data,
                                ),
                                409,
                            )

                        try:
                            db.execute("BEGIN IMMEDIATE")
                            debit_decision = race_condition_defense.atomic_debit(
                                db,
                                account["id"],
                                transfer_data["amount"],
                            )
                            if not debit_decision["debited"]:
                                db.rollback()
                                update_transfer_attempt(app, attempt_id, "rejected", transfer_data["receiver_id"], transfer_data["amount"])
                                record_security_event(
                                    app,
                                    event_type="transfer_atomic_debit_failed",
                                    severity=debit_decision["risk_level"],
                                    username=current_username(app),
                                    user_id=session["user_id"],
                                    account_id=account["id"],
                                    target_account_id=transfer_data["receiver_id"],
                                    details=(
                                        f"Atomic debit failed for transfer of GBP {transfer_data['amount']:.2f} to "
                                        f"{transfer_data['receiver_name']} ({transfer_data['receiver_username']}); "
                                        f"reasons: {', '.join(debit_decision['reasons'])}; "
                                        f"latest balance before attempt: GBP {balance_before:.2f}"
                                    ),
                                )
                                flash("Transfer blocked because the latest balance is insufficient.", "error")
                                return (
                                    render_template(
                                        "transfer.html",
                                        account=account,
                                        users=users,
                                        preview=preview,
                                        form_data=form_data,
                                    ),
                                    409,
                                )

                            db.execute(
                                "UPDATE accounts SET balance = balance + ? WHERE id = ?",
                                (transfer_data["amount"], transfer_data["receiver_id"]),
                            )
                            db.execute(
                                """
                                INSERT INTO transactions (from_account_id, to_account_id, amount, status, note, created_at)
                                VALUES (?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    account["id"],
                                    transfer_data["receiver_id"],
                                    transfer_data["amount"],
                                    "COMPLETED",
                                    transfer_data["note"] or "Transfer",
                                    now_iso(),
                                ),
                            )
                            refreshed_sender_account = db.execute(
                                "SELECT balance FROM accounts WHERE id = ?",
                                (account["id"],),
                            ).fetchone()
                            balance_after = refreshed_sender_account["balance"] if refreshed_sender_account else balance_before - transfer_data["amount"]
                            db.commit()
                        except Exception:
                            db.rollback()
                            raise
                else:
                    balance_before = float(account["balance"])
                    try:
                        db.execute("BEGIN")
                        db.execute(
                            "UPDATE accounts SET balance = balance - ? WHERE id = ?",
                            (transfer_data["amount"], account["id"]),
                        )
                        db.execute(
                            "UPDATE accounts SET balance = balance + ? WHERE id = ?",
                            (transfer_data["amount"], transfer_data["receiver_id"]),
                        )
                        db.execute(
                            """
                            INSERT INTO transactions (from_account_id, to_account_id, amount, status, note, created_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                account["id"],
                                transfer_data["receiver_id"],
                                transfer_data["amount"],
                                "COMPLETED",
                                transfer_data["note"] or "Transfer",
                                now_iso(),
                            ),
                        )
                        refreshed_sender_account = db.execute(
                            "SELECT balance FROM accounts WHERE id = ?",
                            (account["id"],),
                        ).fetchone()
                        balance_after = refreshed_sender_account["balance"] if refreshed_sender_account else balance_before - transfer_data["amount"]
                        db.commit()
                    except Exception:
                        db.rollback()
                        raise
                update_transfer_attempt(app, attempt_id, "completed", transfer_data["receiver_id"], transfer_data["amount"])
                if ENABLE_TRANSFER_DEFENSE:
                    transfer_defense.record_completed_transfer(account["id"])
                record_balance_audit(
                    app,
                    account_id=account["id"],
                    event_type="transfer_debit",
                    amount_delta=-transfer_data["amount"],
                    balance_before=balance_before,
                    balance_after=balance_after,
                    related_account_id=transfer_data["receiver_id"],
                )
                record_security_event(
                    app,
                    event_type="transfer_completed",
                    severity=transfer_data["risk_level"],
                    username=current_username(app),
                    user_id=session["user_id"],
                    account_id=account["id"],
                    target_account_id=transfer_data["receiver_id"],
                    details=(
                        f"Completed transfer of £{transfer_data['amount']:.2f} to "
                        f"{transfer_data['receiver_name']} ({transfer_data['receiver_username']}); "
                        f"flags: {', '.join(transfer_data['risk_flags']) or 'none'}"
                    ),
                )
                flash("Transfer completed successfully.", "success")
                return redirect(url_for("transactions_page"))

        return render_template(
            "transfer.html",
            account=account,
            users=users,
            preview=preview,
            form_data=form_data,
        )

    @app.route("/admin/security")
    @login_required
    def admin_security():
        if current_user_role(app) != "admin":
            flash("You do not have permission to view that page.", "error")
            return redirect(url_for("dashboard"))
        metrics = {
            "failed_logins": query_scalar(app, "SELECT COUNT(*) FROM security_events WHERE event_type = 'login_failure'"),
            "successful_logins": query_scalar(app, "SELECT COUNT(*) FROM security_events WHERE event_type = 'login_success'"),
            "transfers_completed": query_scalar(app, "SELECT COUNT(*) FROM security_events WHERE event_type = 'transfer_completed'"),
            "high_risk_events": query_scalar(app, "SELECT COUNT(*) FROM security_events WHERE severity IN ('high', 'critical')"),
            "transfers_to_mallory": query_scalar(
                app,
                """
                SELECT COUNT(*)
                FROM transactions t
                JOIN accounts a ON t.to_account_id = a.id
                JOIN users u ON a.user_id = u.id
                WHERE u.username = 'mallory'
                """,
            ),
            "request_volume": query_scalar(app, "SELECT COUNT(*) FROM request_logs"),
            "slow_requests": query_scalar(app, "SELECT COUNT(*) FROM request_logs WHERE duration_ms >= 800"),
            "transfer_rejections": query_scalar(app, "SELECT COUNT(*) FROM transfer_attempts WHERE status = 'rejected'"),
            "duplicate_transfer_signals": query_scalar(
                app,
                """
                SELECT COUNT(*)
                FROM (
                    SELECT user_id, from_account_id, to_account_id, amount_value, note, minute_bucket, COUNT(*) AS burst_count
                    FROM (
                        SELECT
                            user_id,
                            from_account_id,
                            to_account_id,
                            amount_value,
                            COALESCE(note, '') AS note,
                            substr(created_at, 1, 16) AS minute_bucket
                        FROM transfer_attempts
                        WHERE status = 'completed'
                    ) grouped_attempts
                    GROUP BY user_id, from_account_id, to_account_id, amount_value, note, minute_bucket
                    HAVING burst_count > 1
                ) suspicious_bursts
                """,
            ),
        }
        attack_overview = {
            "enumerated_usernames": query_scalar(
                app,
                """
                SELECT COUNT(*)
                FROM (
                    SELECT username
                    FROM login_logs
                    WHERE success = 0 AND username != 'unknown'
                    GROUP BY username
                    HAVING COUNT(*) >= 2
                ) usernames
                """,
            ),
            "active_attack_ips": query_scalar(
                app,
                """
                SELECT COUNT(*)
                FROM (
                    SELECT ip_address
                    FROM request_logs
                    GROUP BY ip_address
                    HAVING COUNT(*) >= 10
                ) noisy_ips
                """,
            ),
            "latest_request_burst": query_scalar(
                app,
                """
                SELECT MAX(request_count)
                FROM (
                    SELECT substr(created_at, 1, 16) AS minute_bucket, COUNT(*) AS request_count
                    FROM request_logs
                    GROUP BY minute_bucket
                ) request_bursts
                """,
            ),
        }
        recent_events = query_all(
            app,
            """
            SELECT se.*, u.full_name AS target_account_owner
            FROM security_events se
            LEFT JOIN accounts a ON se.target_account_id = a.id
            LEFT JOIN users u ON a.user_id = u.id
            ORDER BY se.created_at DESC
            LIMIT 20
            """,
        )
        high_risk_transfers = query_all(
            app,
            """
            SELECT
                t.created_at,
                t.amount,
                t.note,
                sender.full_name AS from_name,
                sender_account.account_number AS from_account_number,
                receiver.full_name AS to_name,
                receiver.username AS to_username,
                receiver_account.account_number AS to_account_number
            FROM transactions t
            JOIN accounts sender_account ON t.from_account_id = sender_account.id
            JOIN users sender ON sender_account.user_id = sender.id
            JOIN accounts receiver_account ON t.to_account_id = receiver_account.id
            JOIN users receiver ON receiver_account.user_id = receiver.id
            WHERE receiver.username = 'mallory' OR t.amount >= ?
            ORDER BY t.created_at DESC
            LIMIT 12
            """,
            (HIGH_VALUE_TRANSFER_THRESHOLD,),
        )
        suspicious_login_patterns = query_all(
            app,
            """
            SELECT
                username,
                COUNT(*) AS failure_count,
                COUNT(DISTINCT ip_address) AS unique_ips,
                MIN(attempted_at) AS first_seen,
                MAX(attempted_at) AS last_seen
            FROM login_logs
            WHERE success = 0
            GROUP BY username
            ORDER BY failure_count DESC, last_seen DESC
            LIMIT 8
            """,
        )
        hot_paths = query_all(
            app,
            """
            SELECT
                path,
                method,
                COUNT(*) AS hits,
                ROUND(AVG(duration_ms), 1) AS avg_duration_ms,
                MAX(duration_ms) AS max_duration_ms
            FROM request_logs
            GROUP BY path, method
            ORDER BY hits DESC, avg_duration_ms DESC
            LIMIT 8
            """,
        )
        recent_request_logs = query_all(
            app,
            """
            SELECT created_at, method, path, status_code, duration_ms, ip_address, user_id
            FROM request_logs
            ORDER BY created_at DESC
            LIMIT 20
            """,
        )
        recent_transfer_attempts = query_all(
            app,
            """
            SELECT
                ta.created_at,
                ta.action,
                ta.status,
                ta.amount_text,
                ta.amount_value,
                ta.note,
                sender.username AS from_username,
                receiver.username AS to_username
            FROM transfer_attempts ta
            LEFT JOIN users sender ON ta.user_id = sender.id
            LEFT JOIN accounts target_account ON ta.to_account_id = target_account.id
            LEFT JOIN users receiver ON target_account.user_id = receiver.id
            ORDER BY ta.created_at DESC
            LIMIT 12
            """,
        )
        balance_audits = query_all(
            app,
            """
            SELECT
                ba.created_at,
                ba.event_type,
                ba.amount_delta,
                ba.balance_before,
                ba.balance_after,
                u.username AS account_username,
                related_user.username AS related_username
            FROM balance_audits ba
            LEFT JOIN accounts account ON ba.account_id = account.id
            LEFT JOIN users u ON account.user_id = u.id
            LEFT JOIN accounts related_account ON ba.related_account_id = related_account.id
            LEFT JOIN users related_user ON related_account.user_id = related_user.id
            ORDER BY ba.created_at DESC
            LIMIT 12
            """,
        )
        request_chart = build_chart_series(
            query_all(
                app,
                """
                SELECT substr(created_at, 12, 5) AS label, COUNT(*) AS value
                FROM request_logs
                GROUP BY substr(created_at, 1, 16)
                ORDER BY substr(created_at, 1, 16) DESC
                LIMIT 8
                """
            )
        )
        failed_login_chart = build_chart_series(
            query_all(
                app,
                """
                SELECT substr(attempted_at, 12, 5) AS label, COUNT(*) AS value
                FROM login_logs
                WHERE success = 0
                GROUP BY substr(attempted_at, 1, 16)
                ORDER BY substr(attempted_at, 1, 16) DESC
                LIMIT 8
                """
            )
        )
        transfer_chart = build_chart_series(
            query_all(
                app,
                """
                SELECT substr(created_at, 12, 5) AS label, COUNT(*) AS value
                FROM transfer_attempts
                GROUP BY substr(created_at, 1, 16)
                ORDER BY substr(created_at, 1, 16) DESC
                LIMIT 8
                """
            )
        )
        return render_template(
            "admin_security.html",
            metrics=metrics,
            attack_overview=attack_overview,
            recent_events=recent_events,
            high_risk_transfers=high_risk_transfers,
            suspicious_login_patterns=suspicious_login_patterns,
            hot_paths=hot_paths,
            recent_request_logs=recent_request_logs,
            recent_transfer_attempts=recent_transfer_attempts,
            balance_audits=balance_audits,
            request_chart=request_chart,
            failed_login_chart=failed_login_chart,
            transfer_chart=transfer_chart,
            high_value_threshold=HIGH_VALUE_TRANSFER_THRESHOLD,
        )

    @app.route("/admin/security/export/<dataset>")
    @login_required
    def export_security_dataset(dataset: str):
        if current_user_role(app) != "admin":
            flash("You do not have permission to view that page.", "error")
            return redirect(url_for("dashboard"))

        if dataset == "request_logs":
            rows = query_all(
                app,
                """
                SELECT created_at, method, path, status_code, duration_ms, ip_address, user_id, user_agent
                FROM request_logs
                ORDER BY created_at DESC
                """
            )
            fieldnames = ["created_at", "method", "path", "status_code", "duration_ms", "ip_address", "user_id", "user_agent"]
        elif dataset == "login_failures":
            rows = query_all(
                app,
                """
                SELECT attempted_at, username, success, ip_address
                FROM login_logs
                WHERE success = 0
                ORDER BY attempted_at DESC
                """
            )
            fieldnames = ["attempted_at", "username", "success", "ip_address"]
        elif dataset == "transfer_attempts":
            rows = query_all(
                app,
                """
                SELECT created_at, user_id, from_account_id, to_account_id, amount_text, amount_value, action, status, note
                FROM transfer_attempts
                ORDER BY created_at DESC
                """
            )
            fieldnames = ["created_at", "user_id", "from_account_id", "to_account_id", "amount_text", "amount_value", "action", "status", "note"]
        elif dataset == "balance_audits":
            rows = query_all(
                app,
                """
                SELECT created_at, account_id, related_account_id, event_type, amount_delta, balance_before, balance_after
                FROM balance_audits
                ORDER BY created_at DESC
                """
            )
            fieldnames = ["created_at", "account_id", "related_account_id", "event_type", "amount_delta", "balance_before", "balance_after"]
        else:
            flash("Unknown export dataset.", "error")
            return redirect(url_for("admin_security"))

        response = make_response(export_rows_to_csv(rows, fieldnames))
        response.headers["Content-Type"] = "text/csv; charset=utf-8"
        response.headers["Content-Disposition"] = f"attachment; filename={dataset}.csv"
        return response

    @app.route("/health")
    def health():
        return {"status": "ok", "database": app.config["DATABASE"]}

    with app.app_context():
        init_db(app)

    return app



def login_required(view_func):
    def wrapped_view(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    wrapped_view.__name__ = view_func.__name__
    return wrapped_view



def get_db(app: Flask) -> sqlite3.Connection:
    db = getattr(g, "_database", None)
    if db is None:
        db = sqlite3.connect(app.config["DATABASE"])
        db.row_factory = sqlite3.Row
        g._database = db
    return db



def query_one(app: Flask, query: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
    cur = get_db(app).execute(query, params)
    row = cur.fetchone()
    cur.close()
    return row



def query_all(app: Flask, query: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    cur = get_db(app).execute(query, params)
    rows = cur.fetchall()
    cur.close()
    return rows



def query_scalar(app: Flask, query: str, params: tuple[Any, ...] = ()) -> Any:
    row = query_one(app, query, params)
    if row is None:
        return None
    return row[0]



def build_chart_series(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    ordered_rows = list(reversed(rows))
    max_value = max((row["value"] for row in ordered_rows), default=1)
    return [
        {
            "label": row["label"],
            "value": row["value"],
            "height_pct": max(12, int((row["value"] / max_value) * 100)) if max_value else 12,
        }
        for row in ordered_rows
    ]


def export_rows_to_csv(rows: list[sqlite3.Row], fieldnames: list[str]) -> str:
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({field: prepare_export_value(field, row[field]) for field in fieldnames})
    return buffer.getvalue()


def prepare_export_value(field: str, value: Any) -> Any:
    if field == "ip_address":
        return data_security.mask_ip(value)
    if field in {"details", "note", "user_agent"}:
        return data_security.redact_text(value)
    if isinstance(value, str):
        return data_security.redact_text(value, max_length=255)
    return value


def record_ids_decision(app: Flask, decision: dict[str, Any]) -> None:
    if not ENABLE_IDS_DEFENSE:
        return
    if not decision.get("should_alert"):
        return

    rule = decision["rule"]
    event_type_by_rule = {
        "login_spray_detected": "ids_login_spray_detected",
        "suspicious_client_activity": "ids_suspicious_client_activity",
    }
    event_type = event_type_by_rule.get(rule)
    if event_type is None:
        return

    masked_ip = data_security.mask_ip(decision.get("ip_address"))
    signals = decision.get("signals", {})
    details = (
        f"IDS rule={rule}; client_ip={masked_ip}; "
        f"signals={data_security.redact_text(signals, max_length=320)}"
    )
    record_security_event(
        app,
        event_type=event_type,
        severity="high",
        details=details,
    )


def now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"



def current_username(app: Flask) -> str:
    user = query_one(app, "SELECT username FROM users WHERE id = ?", (session["user_id"],))
    return user["username"]



def current_user_role(app: Flask) -> str | None:
    if session.get("user_id") is None:
        return None
    user = query_one(app, "SELECT role FROM users WHERE id = ?", (session["user_id"],))
    if user is None:
        return None
    return user["role"]


def get_current_account(app: Flask) -> sqlite3.Row:
    account = query_one(app, "SELECT * FROM accounts WHERE user_id = ?", (session["user_id"],))
    if account is None:
        raise RuntimeError("Logged-in user has no linked account. Seed data may be incomplete.")
    return account



def get_transfer_risk_flags(app: Flask, sender_account_id: int, receiver_username: str, amount: float) -> list[str]:
    flags: list[str] = []
    if amount >= HIGH_VALUE_TRANSFER_THRESHOLD:
        flags.append("high_value_amount")

    prior_transfers = query_scalar(
        app,
        "SELECT COUNT(*) FROM transactions WHERE from_account_id = ? AND to_account_id IN (SELECT a.id FROM accounts a JOIN users u ON a.user_id = u.id WHERE u.username = ?)",
        (sender_account_id, receiver_username),
    )
    if not prior_transfers:
        flags.append("new_payee")

    if receiver_username in RISKY_DESTINATION_USERNAMES:
        flags.append("attacker_controlled_destination")

    return flags



def severity_from_flags(flags: list[str]) -> str:
    if "attacker_controlled_destination" in flags:
        return "critical"
    if len(flags) >= 2:
        return "high"
    if len(flags) == 1:
        return "medium"
    return "low"



def validate_transfer_form(
    app: Flask,
    account: sqlite3.Row,
    form_data: dict[str, str],
) -> dict[str, Any] | None:
    try:
        receiver_id = int(form_data["to_account_id"])
        amount = round(float(form_data["amount"]), 2)
    except ValueError:
        flash("Please enter a valid target account and amount.", "error")
        return None

    if amount <= 0:
        flash("Amount must be greater than 0.", "error")
        return None

    if receiver_id == account["id"]:
        flash("You cannot transfer to the same account.", "error")
        return None

    receiver = query_one(
        app,
        """
        SELECT accounts.id, accounts.account_number, users.full_name, users.username
        FROM accounts
        JOIN users ON users.id = accounts.user_id
        WHERE accounts.id = ?
        """,
        (receiver_id,),
    )
    if receiver is None:
        flash("Target account not found.", "error")
        return None

    if account["balance"] < amount:
        flash("Insufficient balance.", "error")
        return None

    risk_flags = get_transfer_risk_flags(app, account["id"], receiver["username"], amount)
    return {
        "receiver_id": receiver["id"],
        "receiver_name": receiver["full_name"],
        "receiver_username": receiver["username"],
        "receiver_account_number": receiver["account_number"],
        "amount": amount,
        "note": form_data["note"],
        "risk_flags": risk_flags,
        "risk_level": severity_from_flags(risk_flags),
    }



def log_login_attempt(app: Flask, username: str, success: bool, ip_address: str) -> None:
    db = get_db(app)
    db.execute(
        "INSERT INTO login_logs (username, success, ip_address, attempted_at) VALUES (?, ?, ?, ?)",
        (username, 1 if success else 0, ip_address, now_iso()),
    )
    db.commit()



def log_request_event(
    app: Flask,
    path: str,
    method: str,
    status_code: int,
    duration_ms: int,
    ip_address: str,
    user_agent: str,
    user_id: int | None,
) -> None:
    db = get_db(app)
    db.execute(
        """
        INSERT INTO request_logs (path, method, status_code, duration_ms, ip_address, user_agent, user_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (path, method, status_code, duration_ms, ip_address, user_agent, user_id, now_iso()),
    )
    db.commit()


def log_transfer_attempt(
    app: Flask,
    user_id: int,
    from_account_id: int,
    to_account_id: int | None,
    amount_text: str,
    action: str,
    status: str,
    note: str,
) -> int:
    try:
        amount_value = round(float(amount_text), 2)
    except ValueError:
        amount_value = None

    db = get_db(app)
    cur = db.execute(
        """
        INSERT INTO transfer_attempts (
            user_id, from_account_id, to_account_id, amount_text, amount_value, action, status, note, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, from_account_id, to_account_id, amount_text, amount_value, action, status, note, now_iso()),
    )
    db.commit()
    return cur.lastrowid


def update_transfer_attempt(
    app: Flask,
    attempt_id: int,
    status: str,
    to_account_id: int | None = None,
    amount_value: float | None = None,
) -> None:
    db = get_db(app)
    db.execute(
        """
        UPDATE transfer_attempts
        SET status = ?, to_account_id = COALESCE(?, to_account_id), amount_value = COALESCE(?, amount_value)
        WHERE id = ?
        """,
        (status, to_account_id, amount_value, attempt_id),
    )
    db.commit()


def record_balance_audit(
    app: Flask,
    account_id: int,
    event_type: str,
    amount_delta: float,
    balance_before: float,
    balance_after: float,
    related_account_id: int | None = None,
) -> None:
    db = get_db(app)
    db.execute(
        """
        INSERT INTO balance_audits (
            account_id, related_account_id, event_type, amount_delta, balance_before, balance_after, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (account_id, related_account_id, event_type, amount_delta, balance_before, balance_after, now_iso()),
    )
    db.commit()


def is_admin_locked_out(app: Flask, username: str) -> bool:
    window_start = (datetime.utcnow() - timedelta(minutes=ADMIN_LOCKOUT_WINDOW_MINUTES)).replace(microsecond=0).isoformat() + "Z"
    recent_failures = query_scalar(
        app,
        """
        SELECT COUNT(*)
        FROM login_logs
        WHERE username = ? AND success = 0 AND attempted_at >= ?
        """,
        (username, window_start),
    )
    return bool(recent_failures and recent_failures >= ADMIN_LOCKOUT_THRESHOLD)


def record_security_event(
    app: Flask,
    event_type: str,
    severity: str,
    details: str,
    username: str | None = None,
    user_id: int | None = None,
    account_id: int | None = None,
    target_account_id: int | None = None,
) -> None:
    db = get_db(app)
    safe_details = data_security.sanitize_security_details(details)
    db.execute(
        """
        INSERT INTO security_events (
            event_type, severity, username, user_id, account_id, target_account_id, details, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (event_type, severity, username, user_id, account_id, target_account_id, safe_details, now_iso()),
    )
    db.commit()



def init_db(app: Flask) -> None:
    db = sqlite3.connect(app.config["DATABASE"])
    db.row_factory = sqlite3.Row

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer',
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            account_number TEXT NOT NULL UNIQUE,
            account_type TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_account_id INTEGER NOT NULL,
            to_account_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (from_account_id) REFERENCES accounts(id),
            FOREIGN KEY (to_account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            success INTEGER NOT NULL,
            ip_address TEXT,
            attempted_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS request_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            method TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            duration_ms INTEGER NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            user_id INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS transfer_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            from_account_id INTEGER NOT NULL,
            to_account_id INTEGER,
            amount_text TEXT NOT NULL,
            amount_value REAL,
            action TEXT NOT NULL,
            status TEXT NOT NULL,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (from_account_id) REFERENCES accounts(id),
            FOREIGN KEY (to_account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS balance_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            related_account_id INTEGER,
            event_type TEXT NOT NULL,
            amount_delta REAL NOT NULL,
            balance_before REAL NOT NULL,
            balance_after REAL NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (account_id) REFERENCES accounts(id),
            FOREIGN KEY (related_account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            username TEXT,
            user_id INTEGER,
            account_id INTEGER,
            target_account_id INTEGER,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (account_id) REFERENCES accounts(id),
            FOREIGN KEY (target_account_id) REFERENCES accounts(id)
        );
        """
    )

    ensure_demo_data(db)

    db.commit()
    db.close()



def ensure_demo_data(db: sqlite3.Connection) -> None:
    admin_password = os.environ.get(ADMIN_PASSWORD_ENV_VAR, DEFAULT_ADMIN_PASSWORD)
    demo_users = [
        ("alice", "Alice Wong", "alice@example.com", "customer", "alice123", "ACC1001", "Current Account", 850.00),
        ("bob", "Bob Patel", "bob@example.com", "customer", "bob123", "ACC1002", "Savings Account", 420.50),
        ("carol", "Carol Smith", "carol@example.com", "customer", "carol123", "ACC1003", "Student Account", 3080.75),
        ("mallory", "Mallory Reed", "mallory@example.com", "customer", "mallory123", "ACC9001", "External Beneficiary", 0.00),
    ]

    user_ids: dict[str, int] = {}
    account_ids: dict[str, int] = {}

    for username, full_name, email, role, password, account_number, account_type, balance in demo_users:
        user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if user is None:
            cur = db.execute(
                "INSERT INTO users (username, full_name, email, role, password_hash) VALUES (?, ?, ?, ?, ?)",
                (username, full_name, email, role, generate_password_hash(password)),
            )
            user_id = cur.lastrowid
        else:
            user_id = user["id"]
        user_ids[username] = user_id

        account = db.execute("SELECT id FROM accounts WHERE user_id = ?", (user_id,)).fetchone()
        if account is None:
            cur = db.execute(
                "INSERT INTO accounts (user_id, account_number, account_type, balance) VALUES (?, ?, ?, ?)",
                (user_id, account_number, account_type, balance),
            )
            account_ids[username] = cur.lastrowid
        else:
            account_ids[username] = account["id"]

    admin = db.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,)).fetchone()
    if admin is None:
        db.execute(
            "INSERT INTO users (username, full_name, email, role, password_hash) VALUES (?, ?, ?, ?, ?)",
            (
                ADMIN_USERNAME,
                "Security Administrator",
                "admin@example.com",
                "admin",
                generate_password_hash(admin_password),
            ),
        )

    existing_transactions = db.execute("SELECT COUNT(*) AS count FROM transactions").fetchone()["count"]
    if existing_transactions == 0:
        transactions = [
            (account_ids["alice"], account_ids["bob"], 55.00, "COMPLETED", "Groceries split", "2026-03-01T09:15:00Z"),
            (account_ids["carol"], account_ids["alice"], 120.00, "COMPLETED", "Rent share", "2026-03-03T14:20:00Z"),
            (account_ids["alice"], account_ids["carol"], 18.50, "COMPLETED", "Cafe payment", "2026-03-05T18:45:00Z"),
            (account_ids["bob"], account_ids["alice"], 9.99, "COMPLETED", "Movie ticket", "2026-03-08T12:05:00Z"),
            (account_ids["carol"], account_ids["bob"], 250.00, "COMPLETED", "Trip refund", "2026-03-10T17:40:00Z"),
        ]
        db.executemany(
            """
            INSERT INTO transactions (from_account_id, to_account_id, amount, status, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            transactions,
        )

    existing_logs = db.execute("SELECT COUNT(*) AS count FROM login_logs").fetchone()["count"]
    if existing_logs == 0:
        login_logs = [
            ("alice", 1, "127.0.0.1", "2026-03-10T08:00:00Z"),
            ("alice", 0, "127.0.0.1", "2026-03-11T08:05:00Z"),
            ("bob", 1, "127.0.0.1", "2026-03-12T11:30:00Z"),
            ("carol", 1, "127.0.0.1", "2026-03-12T13:15:00Z"),
            ("mallory", 1, "127.0.0.1", "2026-03-13T09:45:00Z"),
        ]
        db.executemany(
            "INSERT INTO login_logs (username, success, ip_address, attempted_at) VALUES (?, ?, ?, ?)",
            login_logs,
        )

    existing_request_logs = db.execute("SELECT COUNT(*) AS count FROM request_logs").fetchone()["count"]
    if existing_request_logs == 0:
        request_logs = [
            ("/login", "POST", 200, 124, "127.0.0.1", "SeededBrowser/1.0", user_ids["alice"], "2026-03-11T08:05:00Z"),
            ("/login", "POST", 200, 131, "127.0.0.1", "SeededBrowser/1.0", user_ids["alice"], "2026-03-10T08:00:00Z"),
            ("/transfer", "POST", 302, 164, "127.0.0.1", "SeededBrowser/1.0", user_ids["alice"], "2026-03-14T10:10:00Z"),
            ("/health", "GET", 200, 910, "10.0.0.55", "LoadTest/0.1", None, "2026-03-14T10:10:15Z"),
            ("/health", "GET", 200, 955, "10.0.0.55", "LoadTest/0.1", None, "2026-03-14T10:10:16Z"),
        ]
        db.executemany(
            """
            INSERT INTO request_logs (path, method, status_code, duration_ms, ip_address, user_agent, user_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            request_logs,
        )

    existing_transfer_attempts = db.execute("SELECT COUNT(*) AS count FROM transfer_attempts").fetchone()["count"]
    if existing_transfer_attempts == 0:
        transfer_attempts = [
            (user_ids["alice"], account_ids["alice"], account_ids["bob"], "55.00", 55.00, "confirm", "completed", "Groceries split", "2026-03-01T09:15:00Z"),
            (user_ids["alice"], account_ids["alice"], account_ids["mallory"], "500.00", 500.00, "preview", "previewed", "Urgent transfer", "2026-03-14T10:09:40Z"),
            (user_ids["alice"], account_ids["alice"], account_ids["mallory"], "500.00", 500.00, "confirm", "completed", "Urgent transfer", "2026-03-14T10:10:00Z"),
            (user_ids["alice"], account_ids["alice"], account_ids["mallory"], "500.00", 500.00, "confirm", "completed", "Urgent transfer", "2026-03-14T10:10:05Z"),
        ]
        db.executemany(
            """
            INSERT INTO transfer_attempts (
                user_id, from_account_id, to_account_id, amount_text, amount_value, action, status, note, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            transfer_attempts,
        )

    existing_balance_audits = db.execute("SELECT COUNT(*) AS count FROM balance_audits").fetchone()["count"]
    if existing_balance_audits == 0:
        balance_audits = [
            (account_ids["alice"], account_ids["bob"], "transfer_debit", -55.00, 1305.00, 1250.00, "2026-03-01T09:15:00Z"),
            (account_ids["alice"], account_ids["mallory"], "transfer_debit", -500.00, 1250.00, 750.00, "2026-03-14T10:10:00Z"),
            (account_ids["alice"], account_ids["mallory"], "transfer_debit", -500.00, 750.00, 250.00, "2026-03-14T10:10:05Z"),
        ]
        db.executemany(
            """
            INSERT INTO balance_audits (
                account_id, related_account_id, event_type, amount_delta, balance_before, balance_after, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            balance_audits,
        )

    existing_events = db.execute("SELECT COUNT(*) AS count FROM security_events").fetchone()["count"]
    if existing_events == 0:
        security_events = [
            ("login_success", "low", "alice", user_ids["alice"], account_ids["alice"], None, "Successful seeded login event", "2026-03-10T08:00:00Z"),
            ("login_failure", "medium", "alice", None, None, None, "Repeated incorrect password attempt in seeded data", "2026-03-11T08:05:00Z"),
            ("transfer_completed", "low", "alice", user_ids["alice"], account_ids["alice"], account_ids["bob"], "Seeded peer-to-peer transfer", "2026-03-01T09:15:00Z"),
            ("transfer_completed", "critical", "alice", user_ids["alice"], account_ids["alice"], account_ids["mallory"], "Example suspicious transfer to attacker-controlled mule account", "2026-03-14T10:10:00Z"),
        ]
        db.executemany(
            """
            INSERT INTO security_events (event_type, severity, username, user_id, account_id, target_account_id, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            security_events,
        )


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)

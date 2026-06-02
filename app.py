from __future__ import annotations

import os
import html
import json
import secrets
import sqlite3
import smtplib
from email.message import EmailMessage
from hashlib import sha256
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote_plus, urlencode
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

from dotenv import load_dotenv
from flask import (
    abort,
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
ENV_FILE_CACHE: dict[Path, dict[str, str]] = {}


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
    app.config["DATABASE_PATH"] = os.environ.get("DATABASE_PATH", str(BASE_DIR / "portal.db"))
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
    app.config["PASSWORD_RESET_EXPIRY_MINUTES"] = int(
        os.environ.get("PASSWORD_RESET_EXPIRY_MINUTES", "60")
    )

    @app.before_request
    def load_logged_in_user() -> None:
        client_id = session.get("client_id")
        admin_id = session.get("admin_id")
        g.client = None
        g.admin = None
        if client_id is not None:
            g.client = query_one(
                "select id, email, full_name, preferred_name, phone from clients where id = ?",
                (client_id,),
            )
        if admin_id is not None:
            g.admin = query_one(
                "select id, email, full_name from admins where id = ?",
                (admin_id,),
            )

    @app.teardown_appcontext
    def close_db(_error: Exception | None = None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.route("/")
    def index():
        if g.admin:
            return redirect(url_for("admin_clients"))
        if g.client:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            client = query_one("select * from clients where email = ?", (email,))

            if client is None or not check_password_hash(client["password_hash"], password):
                flash("Check your email and password, then try again.", "error")
                record_audit(None, "login_failed", f"Failed login for {email or 'blank email'}")
                return render_template("login.html", email=email), 401

            session.clear()
            session.permanent = request.form.get("remember_device") == "on"
            session["client_id"] = client["id"]
            record_audit(client["id"], "login", "Client signed in")
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            client = query_one("select id, email, full_name from clients where email = ?", (email,))

            if client is not None:
                token = secrets.token_urlsafe(32)
                token_hash = hash_reset_token(token)
                expires_at = (
                    datetime.now(timezone.utc)
                    + timedelta(minutes=app.config["PASSWORD_RESET_EXPIRY_MINUTES"])
                ).isoformat(timespec="seconds")
                execute(
                    """
                    insert into password_reset_tokens (client_id, token_hash, expires_at, created_at, used_at)
                    values (?, ?, ?, ?, null)
                    """,
                    (client["id"], token_hash, expires_at, now_iso()),
                )
                reset_url = url_for("reset_password", token=token, _external=True)
                send_password_reset_email(client["email"], client["full_name"], reset_url)
                record_audit(client["id"], "password_reset_requested", "Password reset email requested")
            elif email:
                record_audit(None, "password_reset_requested_unknown", f"Password reset requested for {email}")

            flash("If an account exists for that email, a reset link has been sent.", "success")
            return redirect(url_for("login"))

        return render_template("forgot_password.html")

    @app.route("/reset-password/<token>", methods=["GET", "POST"])
    def reset_password(token: str):
        reset = get_valid_password_reset(token)
        if reset is None:
            flash("That password reset link is invalid or has expired.", "error")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not password:
                flash("Add a new password before continuing.", "error")
            elif password != confirm_password:
                flash("Passwords do not match.", "error")
            elif len(password) < 8:
                flash("Use a password with at least 8 characters.", "error")
            else:
                execute(
                    "update clients set password_hash = ? where id = ?",
                    (generate_password_hash(password), reset["client_id"]),
                )
                execute(
                    "update password_reset_tokens set used_at = ? where id = ?",
                    (now_iso(), reset["id"]),
                )
                execute(
                    """
                    update password_reset_tokens
                    set used_at = ?
                    where client_id = ? and used_at is null and id != ?
                    """,
                    (now_iso(), reset["client_id"], reset["id"]),
                )
                record_audit(reset["client_id"], "password_reset_completed", "Client reset password")
                flash("Your password has been updated. Please sign in with your new password.", "success")
                return redirect(url_for("login"))

        return render_template("reset_password.html", token=token)

    @app.route("/create-account", methods=["GET", "POST"])
    def create_account():
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not full_name or not email or not password:
                flash("Add your name, email, and password to create an account.", "error")
            elif password != confirm_password:
                flash("Passwords do not match.", "error")
            elif len(password) < 8:
                flash("Use a password with at least 8 characters.", "error")
            else:
                try:
                    execute(
                        """
                        insert into clients
                            (email, password_hash, full_name, preferred_name, phone, created_at)
                        values (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            email,
                            generate_password_hash(password),
                            full_name,
                            first_name(full_name),
                            "",
                            now_iso(),
                        ),
                    )
                except sqlite3.IntegrityError:
                    flash("An account already exists for that email.", "error")
                else:
                    client = query_one("select id from clients where email = ?", (email,))
                    if client is not None:
                        session.clear()
                        session["client_id"] = client["id"]
                        record_audit(client["id"], "account_created", "Client account created")
                        return redirect(url_for("dashboard"))

        return render_template("create_account.html")

    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            admin = query_one("select * from admins where email = ?", (email,))

            if admin is None or not check_password_hash(admin["password_hash"], password):
                flash("Check your admin email and password, then try again.", "error")
                return render_template("admin_login.html", email=email), 401

            session.clear()
            session.permanent = request.form.get("remember_device") == "on"
            session["admin_id"] = admin["id"]
            return redirect(url_for("admin_clients"))

        return render_template("admin_login.html")

    @app.route("/admin/create-account", methods=["GET", "POST"])
    def admin_create_account():
        requires_setup_code = admin_account_count() > 0
        setup_code = get_setting("THERAPIST_SIGNUP_CODE")

        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            submitted_code = request.form.get("setup_code", "").strip()

            if not full_name or not email or not password:
                flash("Add your name, email, and password to create a therapist account.", "error")
            elif password != confirm_password:
                flash("Passwords do not match.", "error")
            elif len(password) < 8:
                flash("Use a password with at least 8 characters.", "error")
            elif requires_setup_code and (not setup_code or submitted_code != setup_code):
                flash("Enter the therapist setup code to create an account.", "error")
            else:
                try:
                    execute(
                        """
                        insert into admins (email, password_hash, full_name, created_at)
                        values (?, ?, ?, ?)
                        """,
                        (email, generate_password_hash(password), full_name, now_iso()),
                    )
                except sqlite3.IntegrityError:
                    flash("A therapist account already exists for that email.", "error")
                else:
                    admin = query_one("select id from admins where email = ?", (email,))
                    if admin is not None:
                        session.clear()
                        session["admin_id"] = admin["id"]
                        flash("Therapist account created.", "success")
                        return redirect(url_for("admin_clients"))

        return render_template(
            "admin_create_account.html",
            requires_setup_code=requires_setup_code,
            signup_available=not requires_setup_code or bool(setup_code),
        )

    @app.route("/admin/logout", methods=["POST"])
    @admin_required
    def admin_logout():
        session.clear()
        return redirect(url_for("admin_login"))

    @app.route("/admin")
    @admin_required
    def admin_clients():
        clients = query_all(
            """
            select
                c.id,
                c.full_name,
                c.preferred_name,
                c.email,
                c.phone,
                c.created_at,
                count(distinct ts.id) as session_count
            from clients c
            left join therapy_sessions ts on ts.client_id = c.id
            group by c.id
            order by c.full_name
            """
        )
        return render_template("admin_clients.html", clients=clients)

    @app.route("/admin/clients/<int:client_id>")
    @admin_required
    def admin_client_detail(client_id: int):
        client = get_client_or_404(client_id)
        sessions = query_all(
            """
            select
                ts.id,
                ts.session_date,
                ts.title,
                ts.summary,
                ts.key_skills,
                ts.next_steps,
                ts.created_at,
                latest_session_reflection.reflection_text as client_reflection,
                latest_session_reflection.created_at as client_reflection_created_at
            from therapy_sessions ts
            left join (
                select sr.session_id, sr.reflection_text, sr.created_at
                from session_reflections sr
                join (
                    select session_id, max(created_at) as latest_created_at
                    from session_reflections
                    where client_id = ?
                    group by session_id
                ) latest on latest.session_id = sr.session_id and latest.latest_created_at = sr.created_at
                where sr.client_id = ?
            ) latest_session_reflection on latest_session_reflection.session_id = ts.id
            where ts.client_id = ?
            order by ts.session_date desc, ts.created_at desc
            """,
            (client_id, client_id, client_id),
        )
        skill_reflections = query_all(
            """
            select csr.skill_id, csr.reflection_text, csr.practiced_at, csr.created_at, cs.title as skill_title
            from client_skill_reflections csr
            join client_skills cs on cs.id = csr.skill_id
            where csr.client_id = ?
            order by csr.practiced_at desc, csr.created_at desc
            """,
            (client_id,),
        )
        return render_template(
            "admin_client_detail.html",
            client=client,
            sessions=sessions,
            skill_reflections=skill_reflections,
        )

    @app.route("/admin/clients/<int:client_id>/sessions", methods=["POST"])
    @admin_required
    def admin_add_session(client_id: int):
        client = get_client_or_404(client_id)
        session_date = request.form.get("session_date", "").strip()
        title = request.form.get("title", "").strip()
        summary = request.form.get("summary", "").strip()
        key_skills = request.form.get("key_skills", "").strip()
        next_steps = request.form.get("next_steps", "").strip()

        if not title:
            flash("Add a session title before saving.", "error")
        else:
            saved_date = session_date or datetime.now().date().isoformat()
            add_session_for_client(client["id"], saved_date, title, summary, key_skills, next_steps)
            flash("Session saved for the client portal.", "success")
        return redirect(url_for("admin_client_detail", client_id=client_id))

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        record_audit(g.client["id"], "logout", "Client signed out")
        session.clear()
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        sessions = query_all(
            """
            select session_date, title, summary, key_skills, next_steps
            from therapy_sessions
            where client_id = ?
            order by session_date desc, created_at desc
            """,
            (g.client["id"],),
        )
        return render_template(
            "dashboard.html",
            sessions=sessions,
        )

    @app.route("/skills", methods=["GET", "POST"])
    @login_required
    def skills():
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            category = request.form.get("category", "").strip()
            notes = request.form.get("notes", "").strip()
            practiced_at = request.form.get("practiced_at", "").strip()

            if not title:
                flash("Add a skill or intervention name before saving.", "error")
            else:
                execute(
                    """
                    insert into client_skills
                        (client_id, title, category, notes, practiced_at, created_at)
                    values (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        g.client["id"],
                        title,
                        category or "Session skill",
                        notes,
                        practiced_at or datetime.now().date().isoformat(),
                        now_iso(),
                    ),
                )
                record_audit(g.client["id"], "skill_added", f"Added skill: {title}")
                flash("Skill saved.", "success")
                return redirect(url_for("skills"))

        skills_list = query_all(
            """
            select
                cs.id,
                cs.title,
                cs.category,
                cs.notes,
                cs.practiced_at,
                cs.created_at,
                latest_reflection.reflection_text,
                latest_reflection.practiced_at as reflection_practiced_at,
                latest_reflection.created_at as reflection_created_at
            from client_skills cs
            left join (
                select csr.skill_id, csr.reflection_text, csr.practiced_at, csr.created_at
                from client_skill_reflections csr
                join (
                    select skill_id, max(created_at) as latest_created_at
                    from client_skill_reflections
                    where client_id = ?
                    group by skill_id
                ) latest on latest.skill_id = csr.skill_id and latest.latest_created_at = csr.created_at
                where csr.client_id = ?
            ) latest_reflection on latest_reflection.skill_id = cs.id
            where cs.client_id = ?
            order by cs.practiced_at desc, cs.created_at desc
            """,
            (g.client["id"], g.client["id"], g.client["id"]),
        )
        return render_template("skills.html", skills=skills_list)

    @app.route("/skills/<int:skill_id>/reflections", methods=["POST"])
    @login_required
    def add_skill_reflection(skill_id: int):
        skill = query_one(
            "select id from client_skills where id = ? and client_id = ?",
            (skill_id, g.client["id"]),
        )
        if skill is None:
            abort(404)

        reflection_text = request.form.get("reflection_text", "").strip()
        practiced_at = request.form.get("practiced_at", "").strip() or datetime.now().date().isoformat()
        if not reflection_text:
            flash("Write what happened when you tried the skill before saving.", "error")
        else:
            execute(
                """
                insert into client_skill_reflections
                    (client_id, skill_id, reflection_text, practiced_at, created_at)
                values (?, ?, ?, ?, ?)
                """,
                (g.client["id"], skill_id, reflection_text, practiced_at, now_iso()),
            )
            record_audit(g.client["id"], "skill_reflection_added", "Client added skill practice reflection")
            flash("Skill reflection saved.", "success")
        return redirect(url_for("skills"))

    @app.route("/sessions")
    @login_required
    def sessions():
        session_list = query_all(
            """
            select
                ts.id,
                ts.session_date,
                ts.title,
                ts.summary,
                ts.key_skills,
                ts.next_steps,
                ts.created_at,
                latest_reflection.reflection_text,
                latest_reflection.created_at as reflection_created_at
            from therapy_sessions ts
            left join (
                select sr.session_id, sr.reflection_text, sr.created_at
                from session_reflections sr
                join (
                    select session_id, max(created_at) as latest_created_at
                    from session_reflections
                    where client_id = ?
                    group by session_id
                ) latest on latest.session_id = sr.session_id and latest.latest_created_at = sr.created_at
                where sr.client_id = ?
            ) latest_reflection on latest_reflection.session_id = ts.id
            where ts.client_id = ?
            order by ts.session_date desc, ts.created_at desc
            """,
            (g.client["id"], g.client["id"], g.client["id"]),
        )
        return render_template("sessions.html", sessions=session_list)

    @app.route("/sessions/<int:session_id>/reflections", methods=["POST"])
    @login_required
    def add_session_reflection(session_id: int):
        therapy_session = query_one(
            "select id from therapy_sessions where id = ? and client_id = ?",
            (session_id, g.client["id"]),
        )
        if therapy_session is None:
            abort(404)

        reflection_text = request.form.get("reflection_text", "").strip()
        if not reflection_text:
            flash("Write a session reflection before saving.", "error")
        else:
            execute(
                """
                insert into session_reflections (client_id, session_id, reflection_text, created_at)
                values (?, ?, ?, ?)
                """,
                (g.client["id"], session_id, reflection_text, now_iso()),
            )
            record_audit(g.client["id"], "session_reflection_added", "Client added session reflection")
            flash("Session reflection saved.", "success")
        return redirect(url_for("sessions"))

    @app.route("/profile")
    @login_required
    def profile():
        return render_template("profile.html")

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}

    return app


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        db_path = Path(current_app_config("DATABASE_PATH"))
        db_path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
    return g.db


def current_app_config(key: str) -> str:
    from flask import current_app

    return str(current_app.config[key])


def query_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    return get_db().execute(sql, params).fetchone()


def query_all(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    return get_db().execute(sql, params).fetchall()


def execute(sql: str, params: tuple = ()) -> None:
    db = get_db()
    db.execute(sql, params)
    db.commit()


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.client is None:
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.admin is None:
            return redirect(url_for("admin_login"))
        return view(**kwargs)

    return wrapped_view


def admin_account_count() -> int:
    row = query_one("select count(*) as admin_count from admins")
    return int(row["admin_count"] if row is not None else 0)


def get_client_or_404(client_id: int) -> sqlite3.Row:
    client = query_one(
        "select id, email, full_name, preferred_name, phone, created_at from clients where id = ?",
        (client_id,),
    )
    if client is None:
        abort(404)
    return client


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def record_audit(client_id: int | None, event_type: str, detail: str) -> None:
    execute(
        """
        insert into audit_events (client_id, event_type, detail, created_at)
        values (?, ?, ?, ?)
        """,
        (client_id, event_type, detail, now_iso()),
    )


def hash_reset_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def get_valid_password_reset(token: str) -> sqlite3.Row | None:
    reset = query_one(
        """
        select prt.id, prt.client_id, prt.expires_at
        from password_reset_tokens prt
        join clients c on c.id = prt.client_id
        where prt.token_hash = ? and prt.used_at is null
        """,
        (hash_reset_token(token),),
    )
    if reset is None:
        return None

    try:
        expires_at = datetime.fromisoformat(reset["expires_at"])
    except ValueError:
        return None

    if expires_at <= datetime.now(timezone.utc):
        execute("update password_reset_tokens set used_at = ? where id = ?", (now_iso(), reset["id"]))
        return None

    return reset


def send_password_reset_email(to_email: str, full_name: str, reset_url: str) -> bool:
    from flask import current_app

    subject = "Reset your TMG Psychology client portal password"
    greeting_name = first_name(full_name) or "there"
    body = f"""Hi {greeting_name},

We received a request to reset the password for your TMG Psychology client portal account.

Use this secure link to choose a new password:
{reset_url}

This link expires in {current_app.config["PASSWORD_RESET_EXPIRY_MINUTES"]} minutes. If you did not request this, you can ignore this email.

TMG Psychology
"""
    return send_email(to_email, subject, body)


def send_email(to_email: str, subject: str, body: str) -> bool:
    provider = get_setting("MAIL_PROVIDER").lower()
    if provider == "graph" or (not provider and graph_mail_configured()):
        return send_graph_email(to_email, subject, body)
    return send_smtp_email(to_email, subject, body)


def send_graph_email(to_email: str, subject: str, body: str) -> bool:
    from flask import current_app

    mailbox = get_graph_mailbox()
    if not mailbox:
        current_app.logger.error("Microsoft Graph mailbox is not configured; password reset email was not sent.")
        return False

    try:
        token = get_graph_access_token()
        payload = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "HTML",
                    "content": format_email_html(body),
                },
                "toRecipients": [{"emailAddress": {"address": to_email}}],
            },
            "saveToSentItems": True,
        }
        graph_json(
            "POST",
            f"https://graph.microsoft.com/v1.0/users/{quote_plus(mailbox)}/sendMail",
            token,
            payload,
        )
    except Exception as exc:
        current_app.logger.exception("Failed to send password reset email via Microsoft Graph: %s", exc)
        return False

    return True


def send_smtp_email(to_email: str, subject: str, body: str) -> bool:
    from flask import current_app

    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    if not smtp_host:
        current_app.logger.error("SMTP_HOST is not configured; password reset email was not sent.")
        return False

    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USERNAME", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "")
    use_tls = os.environ.get("SMTP_USE_TLS", "true").strip().lower() not in {"0", "false", "no"}
    use_ssl = os.environ.get("SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes"}
    from_email = os.environ.get("MAIL_FROM", smtp_user).strip()
    from_name = os.environ.get("MAIL_FROM_NAME", "TMG Psychology").strip()

    if not from_email:
        current_app.logger.error("MAIL_FROM or SMTP_USERNAME must be configured for outgoing email.")
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = f"{from_name} <{from_email}>"
    message["To"] = to_email
    message.set_content(body)

    try:
        smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
        with smtp_class(smtp_host, smtp_port, timeout=15) as smtp:
            if use_tls and not use_ssl:
                smtp.starttls()
            if smtp_user and smtp_password:
                smtp.login(smtp_user, smtp_password)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        current_app.logger.exception("Failed to send password reset email: %s", exc)
        return False

    return True


def get_setting(name: str, default: str = "") -> str:
    value = os.environ.get(name, "").strip()
    if value:
        return value

    for env_path in get_extra_env_paths():
        value = load_env_file(env_path).get(name, "").strip()
        if value:
            return value

    return default


def get_extra_env_paths() -> list[Path]:
    paths = []
    configured = os.environ.get("GRAPH_ENV_FILE", "").strip() or os.environ.get(
        "MICROSOFT_GRAPH_ENV_FILE", ""
    ).strip()
    if configured:
        paths.append(Path(configured).expanduser())
    paths.append(BASE_DIR / ".env")
    return paths


def load_env_file(path: Path) -> dict[str, str]:
    path = path.resolve()
    if path in ENV_FILE_CACHE:
        return ENV_FILE_CACHE[path]

    values = {}
    if path.exists():
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")

    ENV_FILE_CACHE[path] = values
    return values


def graph_mail_configured() -> bool:
    return all(get_setting(name) for name in ("MS_TENANT_ID", "MS_CLIENT_ID", "MS_CLIENT_SECRET"))


def get_graph_mailbox() -> str:
    return (
        get_setting("OUTLOOK_EMAIL_ADDRESS")
        or get_setting("MS_SENDER_EMAIL")
        or get_setting("OUTLOOK_CALENDAR_EMAIL")
        or get_setting("MAIL_FROM")
    )


def get_graph_access_token() -> str:
    tenant = get_setting("MS_TENANT_ID")
    client_id = get_setting("MS_CLIENT_ID")
    client_secret = get_setting("MS_CLIENT_SECRET")
    if not tenant or not client_id or not client_secret:
        raise RuntimeError("Microsoft Graph credentials are missing")

    payload = urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
    ).encode("utf-8")
    req = UrlRequest(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    access_token = data.get("access_token", "")
    if not access_token:
        raise RuntimeError("Graph token response did not include access_token")
    return access_token


def graph_json(method: str, url: str, access_token: str, payload: dict | None = None) -> dict:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = UrlRequest(url, data=data, method=method, headers=headers)
    try:
        with urlopen(req, timeout=20) as resp:
            text = resp.read().decode("utf-8")
            return json.loads(text) if text else {}
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Graph request failed: HTTP {exc.code} {body}") from exc


def format_email_html(value: str) -> str:
    text = str(value or "").strip()
    lower_text = text.lower()
    if any(tag in lower_text for tag in ("<br", "<p", "<div", "<span", "<table", "<ul", "<ol", "<html")):
        return text
    escaped = html.escape(text)
    return "<div>" + escaped.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>") + "</div>"


def parse_skill_lines(value: str) -> list[str]:
    skills = []
    for raw_line in value.splitlines():
        skill = raw_line.strip(" -\t")
        if skill:
            skills.append(skill)
    return skills


def first_name(value: str) -> str:
    parts = value.strip().split()
    return parts[0] if parts else ""


def add_skill_for_client(
    client_id: int,
    title: str,
    category: str,
    notes: str,
    practiced_at: str,
) -> None:
    execute(
        """
        insert into client_skills (client_id, title, category, notes, practiced_at, created_at)
        values (?, ?, ?, ?, ?, ?)
        """,
        (client_id, title, category, notes, practiced_at, now_iso()),
    )
    record_audit(client_id, "skill_added", f"Added skill: {title}")


def add_session_for_client(
    client_id: int,
    session_date: str,
    title: str,
    summary: str,
    key_skills: str,
    next_steps: str,
) -> None:
    execute(
        """
        insert into therapy_sessions
            (client_id, session_date, title, summary, key_skills, next_steps, created_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (client_id, session_date, title, summary, key_skills, next_steps, now_iso()),
    )
    for skill in parse_skill_lines(key_skills):
        add_skill_for_client(
            client_id,
            skill,
            "Session skill",
            f"Added from session: {title}",
            session_date,
        )
    record_audit(client_id, "session_added", f"Added session: {title}")


def init_db(app: Flask) -> None:
    with app.app_context():
        db = get_db()
        db.executescript(
            """
            create table if not exists clients (
                id integer primary key autoincrement,
                email text not null unique,
                password_hash text not null,
                full_name text not null,
                preferred_name text,
                phone text,
                created_at text not null
            );

            create table if not exists admins (
                id integer primary key autoincrement,
                email text not null unique,
                password_hash text not null,
                full_name text not null,
                created_at text not null
            );

            create table if not exists client_skills (
                id integer primary key autoincrement,
                client_id integer not null references clients(id),
                title text not null,
                category text not null,
                notes text,
                practiced_at text not null,
                created_at text not null
            );

            create table if not exists therapy_sessions (
                id integer primary key autoincrement,
                client_id integer not null references clients(id),
                session_date text not null,
                title text not null,
                summary text,
                key_skills text,
                next_steps text,
                created_at text not null
            );

            create table if not exists session_reflections (
                id integer primary key autoincrement,
                client_id integer not null references clients(id),
                session_id integer not null references therapy_sessions(id),
                reflection_text text not null,
                created_at text not null
            );

            create table if not exists client_skill_reflections (
                id integer primary key autoincrement,
                client_id integer not null references clients(id),
                skill_id integer not null references client_skills(id),
                reflection_text text not null,
                practiced_at text not null,
                created_at text not null
            );

            create table if not exists audit_events (
                id integer primary key autoincrement,
                client_id integer references clients(id),
                event_type text not null,
                detail text not null,
                created_at text not null
            );

            create table if not exists password_reset_tokens (
                id integer primary key autoincrement,
                client_id integer not null references clients(id),
                token_hash text not null unique,
                expires_at text not null,
                created_at text not null,
                used_at text
            );

            create index if not exists idx_password_reset_tokens_client
                on password_reset_tokens(client_id);
            create index if not exists idx_password_reset_tokens_token_hash
                on password_reset_tokens(token_hash);
            create index if not exists idx_session_reflections_session
                on session_reflections(session_id);
            create index if not exists idx_client_skill_reflections_skill
                on client_skill_reflections(skill_id);
            """
        )
        db.commit()
        seed_demo_data()
        ensure_demo_session_data()
        ensure_master_account()


def seed_demo_data() -> None:
    existing = query_one("select id from clients limit 1")
    if existing is not None:
        return

    created_at = now_iso()
    password_hash = generate_password_hash("change-me-now")
    execute(
        """
        insert into clients (email, password_hash, full_name, preferred_name, phone, created_at)
        values (?, ?, ?, ?, ?, ?)
        """,
        (
            "client@example.com",
            password_hash,
            "Example Client",
            "Example",
            "+61 400 000 000",
            created_at,
        ),
    )
    client = query_one("select id from clients where email = ?", ("client@example.com",))
    if client is None:
        return

    client_id = client["id"]
    execute(
        """
        insert into client_skills (client_id, title, category, notes, practiced_at, created_at)
        values (?, ?, ?, ?, ?, ?)
        """,
        (
            client_id,
            "Grounding practice",
            "Regulation",
            "Notice five things you can see, four you can feel, three you can hear, two you can smell, and one you can taste.",
            datetime.now().date().isoformat(),
            created_at,
        ),
    )
    record_audit(client_id, "seed", "Demo client account created")


def ensure_demo_session_data() -> None:
    client = query_one("select id from clients order by id limit 1")
    if client is None:
        return

    existing = query_one("select id from therapy_sessions where client_id = ? limit 1", (client["id"],))
    if existing is not None:
        return

    session_date = datetime.now().date().isoformat()
    execute(
        """
        insert into therapy_sessions
            (client_id, session_date, title, summary, key_skills, next_steps, created_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            client["id"],
            session_date,
            "Building regulation skills",
            "Session focused on noticing early signs of escalation and choosing a grounding strategy before the situation intensifies.",
            "Grounding practice\nBreathing reset",
            "Practise the grounding sequence once daily and note when it feels easier to access.",
            now_iso(),
        ),
    )


def ensure_master_account() -> None:
    existing = query_one("select id from admins limit 1")
    if existing is not None:
        return

    email = os.environ.get("MASTER_EMAIL", "").strip().lower()
    password = os.environ.get("MASTER_PASSWORD", "")
    full_name = os.environ.get("MASTER_NAME", "TMG Psychology").strip()
    if not email or not password:
        if os.environ.get("FLASK_ENV") == "production":
            return
        email = "admin@example.com"
        password = "change-me-now"

    execute(
        """
        insert into admins (email, password_hash, full_name, created_at)
        values (?, ?, ?, ?)
        """,
        (email, generate_password_hash(password), full_name, now_iso()),
    )


app = create_app()
init_db(app)


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "3020"))
    app.run(host=host, port=port, debug=os.environ.get("FLASK_ENV") == "development")

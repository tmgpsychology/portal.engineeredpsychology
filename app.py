from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

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


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
    app.config["DATABASE_PATH"] = os.environ.get("DATABASE_PATH", str(BASE_DIR / "portal.db"))
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

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
                count(distinct ts.id) as session_count,
                count(distinct cs.id) as skill_count
            from clients c
            left join therapy_sessions ts on ts.client_id = c.id
            left join client_skills cs on cs.client_id = c.id
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
            select id, session_date, title, summary, key_skills, next_steps, created_at
            from therapy_sessions
            where client_id = ?
            order by session_date desc, created_at desc
            """,
            (client_id,),
        )
        skills = query_all(
            """
            select id, title, category, notes, practiced_at, created_at
            from client_skills
            where client_id = ?
            order by practiced_at desc, created_at desc
            """,
            (client_id,),
        )
        activity = query_all(
            """
            select event_type, detail, created_at
            from audit_events
            where client_id = ?
            order by created_at desc
            limit 12
            """,
            (client_id,),
        )
        return render_template(
            "admin_client_detail.html",
            client=client,
            sessions=sessions,
            skills=skills,
            activity=activity,
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

    @app.route("/admin/clients/<int:client_id>/skills", methods=["POST"])
    @admin_required
    def admin_add_skill(client_id: int):
        client = get_client_or_404(client_id)
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "").strip()
        notes = request.form.get("notes", "").strip()
        practiced_at = request.form.get("practiced_at", "").strip()

        if not title:
            flash("Add a skill or intervention name before saving.", "error")
        else:
            add_skill_for_client(
                client["id"],
                title,
                category or "Session skill",
                notes,
                practiced_at or datetime.now().date().isoformat(),
            )
            flash("Skill saved for the client portal.", "success")
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
        messages = query_all(
            """
            select subject, body, created_at, sender_label
            from messages
            where client_id = ?
            order by created_at desc
            limit 5
            """,
            (g.client["id"],),
        )
        documents = query_all(
            """
            select title, description, status, uploaded_at
            from documents
            where client_id = ?
            order by uploaded_at desc
            limit 5
            """,
            (g.client["id"],),
        )
        skills = query_all(
            """
            select title, category, practiced_at
            from client_skills
            where client_id = ?
            order by practiced_at desc, created_at desc
            limit 4
            """,
            (g.client["id"],),
        )
        activity = query_all(
            """
            select event_type, detail, created_at
            from audit_events
            where client_id = ?
            order by created_at desc
            limit 8
            """,
            (g.client["id"],),
        )
        sessions = query_all(
            """
            select session_date, title, key_skills
            from therapy_sessions
            where client_id = ?
            order by session_date desc, created_at desc
            limit 3
            """,
            (g.client["id"],),
        )
        return render_template(
            "dashboard.html",
            messages=messages,
            documents=documents,
            skills=skills,
            sessions=sessions,
            activity=activity,
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
            select title, category, notes, practiced_at, created_at
            from client_skills
            where client_id = ?
            order by practiced_at desc, created_at desc
            """,
            (g.client["id"],),
        )
        return render_template("skills.html", skills=skills_list)

    @app.route("/sessions")
    @login_required
    def sessions():
        session_list = query_all(
            """
            select session_date, title, summary, key_skills, next_steps, created_at
            from therapy_sessions
            where client_id = ?
            order by session_date desc, created_at desc
            """,
            (g.client["id"],),
        )
        return render_template("sessions.html", sessions=session_list)

    @app.route("/clinician/sessions", methods=["GET", "POST"])
    @admin_required
    def clinician_sessions():
        if request.method == "GET":
            return redirect(url_for("admin_clients"))
        clients = query_all("select id, full_name, email from clients order by full_name")
        if request.method == "POST":
            client_id = int(request.form.get("client_id", 0))
            session_date = request.form.get("session_date", "").strip()
            title = request.form.get("title", "").strip()
            summary = request.form.get("summary", "").strip()
            key_skills = request.form.get("key_skills", "").strip()
            next_steps = request.form.get("next_steps", "").strip()

            if not title:
                flash("Add a session title before saving.", "error")
            else:
                saved_date = session_date or datetime.now().date().isoformat()
                add_session_for_client(client_id, saved_date, title, summary, key_skills, next_steps)
                flash("Session saved.", "success")
                return redirect(url_for("clinician_sessions"))

        recent_sessions = query_all(
            """
            select ts.session_date, ts.title, ts.summary, ts.key_skills, ts.next_steps, c.full_name
            from therapy_sessions ts
            join clients c on c.id = ts.client_id
            order by ts.session_date desc, ts.created_at desc
            limit 8
            """,
        )
        return render_template(
            "clinician_sessions.html",
            clients=clients,
            recent_sessions=recent_sessions,
        )

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

            create table if not exists messages (
                id integer primary key autoincrement,
                client_id integer not null references clients(id),
                sender_label text not null,
                subject text not null,
                body text not null,
                created_at text not null
            );

            create table if not exists documents (
                id integer primary key autoincrement,
                client_id integer not null references clients(id),
                title text not null,
                description text,
                status text not null default 'available',
                uploaded_at text not null
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

            create table if not exists audit_events (
                id integer primary key autoincrement,
                client_id integer references clients(id),
                event_type text not null,
                detail text not null,
                created_at text not null
            );
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
        insert into messages (client_id, sender_label, subject, body, created_at)
        values (?, ?, ?, ?, ?)
        """,
        (
            client_id,
            "Engineered Psychology",
            "Welcome to your portal",
            "This is the first placeholder message. We can replace this with secure messaging next.",
            created_at,
        ),
    )
    execute(
        """
        insert into documents (client_id, title, description, status, uploaded_at)
        values (?, ?, ?, ?, ?)
        """,
        (
            client_id,
            "Getting started",
            "A placeholder document entry for the first portal dashboard.",
            "available",
            created_at,
        ),
    )
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

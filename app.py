from __future__ import annotations

import os
import base64
import html
import json
import re
import secrets
import sqlite3
import smtplib
import sys
from email.message import EmailMessage
from hashlib import sha256
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote_plus, urlencode
from urllib.request import Request as UrlRequest
from urllib.request import urlopen
from zoneinfo import ZoneInfo

from dotenv import load_dotenv
from flask import (
    abort,
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
ENV_FILE_CACHE: dict[Path, dict[str, str]] = {}
DEFAULT_TIMEZONE = "Australia/Sydney"
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
DEFAULT_REMINDER_MESSAGE = (
    "Hi {first_name}, this is a reminder from TMG Psychology to add any notes, "
    "reflections, or practice updates to your Engineered Psychology portal: {link}"
)
REMINDER_TARGET_OPTIONS = (
    ("/sessions", "Sessions and session notes"),
    ("/skills", "Skills and practice notes"),
    ("/dashboard", "Today behaviour check-in"),
    ("/profile", "Profile"),
)
FOCUS_AREAS = (
    "Mood and motivation",
    "Anxiety and avoidance",
    "Anger or emotional reactivity",
    "Substance use",
    "Relationship communication",
    "Sleep routine",
    "Self-worth",
    "Study or work habits",
    "Parenting behaviour",
    "Other",
)
BARRIER_TAGS = (
    "Forgot",
    "Too overwhelmed",
    "Anxious",
    "Low mood",
    "Conflict",
    "No time",
    "Too tired",
    "Other",
)
HELPED_TAGS = (
    "Reminder",
    "Support person",
    "Smaller task",
    "Reward",
    "Values reminder",
)


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")
    app.config["DATABASE_PATH"] = os.environ.get("DATABASE_PATH", str(BASE_DIR / "portal.db"))
    app.config["SESSION_UPLOAD_FOLDER"] = os.environ.get(
        "SESSION_UPLOAD_FOLDER",
        str(BASE_DIR / "session_uploads"),
    )
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", str(MAX_UPLOAD_BYTES)))
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
            return redirect(get_safe_next_url() or url_for("dashboard"))

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
        invite_token = request.form.get("invite_token", "").strip() or request.args.get("invite", "").strip()
        portal_invite = get_valid_portal_invite(invite_token) if invite_token else None
        used_invite = get_used_portal_invite(invite_token) if invite_token and portal_invite is None else None
        if invite_token and used_invite is not None:
            flash("That portal profile has already been created. Please sign in.", "success")
            return redirect(url_for("login"))
        if request.method == "GET" and invite_token and portal_invite is None:
            flash("That portal invite link is invalid. You can still create an account manually.", "error")
        invite = invite_context(portal_invite, invite_token)

        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            phone = request.form.get("phone", "").strip()
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
                            phone,
                            now_iso(),
                        ),
                    )
                except sqlite3.IntegrityError:
                    flash("An account already exists for that email.", "error")
                else:
                    client = query_one("select id from clients where email = ?", (email,))
                    if client is not None:
                        if portal_invite is not None:
                            mark_portal_invite_used(portal_invite["id"], client["id"])
                        session.clear()
                        session["client_id"] = client["id"]
                        record_audit(client["id"], "account_created", "Client account created")
                        return redirect(url_for("dashboard"))

        return render_template("create_account.html", invite=invite)

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
                count(distinct ts.id) as session_count,
                active_goal.focus_area as goal_area,
                active_goal.frequency_target as frequency_target,
                coalesce(weekly.completed_count, 0) as completed_count,
                coalesce(weekly.checkin_count, 0) as checkin_count,
                coalesce(weekly.avg_mood, 0) as avg_mood
            from clients c
            left join therapy_sessions ts on ts.client_id = c.id
            left join (
                select *
                from change_goals cg
                where cg.status = 'active'
                  and cg.id = (
                    select id
                    from change_goals newer
                    where newer.client_id = cg.client_id and newer.status = 'active'
                    order by newer.created_at desc
                    limit 1
                  )
            ) active_goal on active_goal.client_id = c.id
            left join (
                select
                    client_id,
                    goal_id,
                    sum(case when completed_status = 'yes' then 1 else 0 end) as completed_count,
                    count(*) as checkin_count,
                    avg(nullif(mood_rating, 0)) as avg_mood
                from daily_checkins
                where checkin_date >= date('now', '-6 days')
                group by client_id, goal_id
            ) weekly on weekly.client_id = c.id and weekly.goal_id = active_goal.id
            group by c.id
            order by c.full_name
            """
        )
        return render_template(
            "admin_clients.html",
            clients=clients,
            portal_invites_configured=twilio_sms_configured(),
        )

    @app.route("/admin/invite-sms", methods=["POST"])
    @admin_required
    def admin_send_invite_sms():
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        normalized_phone = normalize_phone_number(phone)

        if not normalized_phone:
            flash("Add a mobile number before sending the portal invite.", "error")
            return redirect(url_for("admin_clients"))
        if not twilio_sms_configured():
            flash("Twilio is not configured for this portal yet.", "error")
            return redirect(url_for("admin_clients"))

        invite_token = create_portal_invite(full_name, email, normalized_phone)
        invite_url = build_create_account_url(invite_token)
        message = build_portal_invite_sms(full_name, invite_url)

        try:
            _from_number, message_sid = send_twilio_sms(normalized_phone, message)
        except Exception as exc:
            from flask import current_app

            current_app.logger.exception("Failed to send portal invite SMS: %s", exc)
            flash("Portal invite SMS could not be sent. Check the Twilio settings.", "error")
        else:
            detail_name = full_name or email or normalized_phone
            record_audit(None, "portal_invite_sms_sent", f"Sent portal invite to {detail_name}: {message_sid}")
            flash("Portal invite SMS sent.", "success")

        return redirect(url_for("admin_clients"))

    @app.route("/admin/clients/<int:client_id>")
    @admin_required
    def admin_client_detail(client_id: int):
        client = get_client_or_404(client_id)
        sessions = get_session_materials(client_id)
        skill_reflections = query_all(
            """
            select
                csr.skill_id,
                csr.reflection_text,
                csr.practiced_at,
                csr.created_at,
                csr.author_role,
                cs.title as skill_title
            from client_skill_reflections csr
            join client_skills cs on cs.id = csr.skill_id
            where csr.client_id = ?
            order by csr.practiced_at desc, csr.created_at desc
            """,
            (client_id,),
        )
        active_goal = get_active_change_goal(client_id)
        goal_summary = get_goal_summary(active_goal["id"]) if active_goal else None
        recent_checkins = get_recent_goal_checkins(active_goal["id"], limit=14) if active_goal else []
        diagnostic = get_latest_change_loop_review(client_id)
        reminder_schedule = get_portal_reminder_schedule(client_id)
        return render_template(
            "admin_client_detail.html",
            client=client,
            active_goal=active_goal,
            focus_areas=FOCUS_AREAS,
            goal_summary=goal_summary,
            recent_checkins=recent_checkins,
            diagnostic=diagnostic,
            sessions=sessions,
            skills=get_client_skills_with_latest_reflection(client_id),
            skill_reflections=skill_reflections,
            reminder_schedule=reminder_schedule,
            reminder_target_options=REMINDER_TARGET_OPTIONS,
            portal_reminders_configured=twilio_sms_configured(),
        )

    @app.route("/admin/clients/<int:client_id>/change-goals", methods=["POST"])
    @admin_required
    def admin_save_change_goal(client_id: int):
        client = get_client_or_404(client_id)
        focus_area = request.form.get("focus_area", "").strip()
        values_link = request.form.get("values_link", "").strip()
        behaviour_target = request.form.get("behaviour_target", "").strip()
        tiny_behaviour = request.form.get("tiny_behaviour", "").strip()
        cue = request.form.get("cue", "").strip()
        backup_version = request.form.get("backup_version", "").strip()
        frequency_target = parse_positive_int(request.form.get("frequency_target"), default=5, maximum=7)
        confidence_rating = parse_positive_int(request.form.get("confidence_rating"), default=7, maximum=10)

        if not behaviour_target or not tiny_behaviour or not cue:
            flash("Add a behaviour target, tiny behaviour, and cue before saving.", "error")
        else:
            save_change_goal(
                client["id"],
                focus_area or "Behaviour change",
                values_link,
                behaviour_target,
                tiny_behaviour,
                cue,
                backup_version,
                frequency_target,
                confidence_rating,
            )
            flash("Behaviour goal saved and set as active.", "success")
        return redirect(url_for("admin_client_detail", client_id=client_id))

    @app.route("/admin/clients/<int:client_id>/change-review", methods=["POST"])
    @admin_required
    def admin_save_change_review(client_id: int):
        client = get_client_or_404(client_id)
        active_goal = get_active_change_goal(client["id"])
        if active_goal is None:
            flash("Create an active behaviour goal before saving a loop review.", "error")
            return redirect(url_for("admin_client_detail", client_id=client_id))

        breakdown_points = request.form.getlist("breakdown_points")
        recommended_adjustment = request.form.get("recommended_adjustment", "").strip()
        session_agenda = request.form.get("session_agenda", "").strip()
        execute(
            """
            insert into therapist_reviews
                (client_id, goal_id, review_date, breakdown_points, recommended_adjustment, session_agenda, created_at)
            values (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client["id"],
                active_goal["id"],
                datetime.now().date().isoformat(),
                json.dumps(breakdown_points),
                recommended_adjustment,
                session_agenda,
                now_iso(),
            ),
        )
        record_audit(client["id"], "change_loop_review_added", "Therapist saved change loop diagnostic")
        flash("Change loop diagnostic saved.", "success")
        return redirect(url_for("admin_client_detail", client_id=client_id))

    @app.route("/admin/clients/<int:client_id>/reminder-schedule", methods=["POST"])
    @admin_required
    def admin_update_reminder_schedule(client_id: int):
        client = get_client_or_404(client_id)
        enabled = request.form.get("enabled") == "on"
        frequency_days = parse_positive_int(request.form.get("frequency_days"), default=1, maximum=30)
        send_time_local = request.form.get("send_time_local", "").strip()
        target_path = request.form.get("target_path", "").strip()
        message_template = request.form.get("message_template", "").strip()

        if enabled and not normalize_phone_number(client["phone"]):
            flash("Add a mobile number to this client before enabling SMS reminders.", "error")
            return redirect(url_for("admin_client_detail", client_id=client_id))
        if enabled and not twilio_sms_configured():
            flash("Twilio is not configured for this portal yet.", "error")
            return redirect(url_for("admin_client_detail", client_id=client_id))
        if not valid_local_time(send_time_local):
            flash("Choose a valid reminder time.", "error")
            return redirect(url_for("admin_client_detail", client_id=client_id))
        if target_path not in dict(REMINDER_TARGET_OPTIONS):
            flash("Choose a valid reminder page.", "error")
            return redirect(url_for("admin_client_detail", client_id=client_id))

        save_portal_reminder_schedule(
            client_id=client["id"],
            enabled=enabled,
            frequency_days=frequency_days,
            send_time_local=send_time_local,
            target_path=target_path,
            message_template=message_template,
        )
        flash("Portal SMS reminder schedule saved.", "success")
        return redirect(url_for("admin_client_detail", client_id=client_id))

    @app.route("/admin/clients/<int:client_id>/sessions", methods=["POST"])
    @admin_required
    def admin_add_session(client_id: int):
        client = get_client_or_404(client_id)
        session_date = request.form.get("session_date", "").strip() or datetime.now().date().isoformat()
        title = request.form.get("title", "").strip() or "Session material"
        summary = request.form.get("summary", "").strip()
        next_steps = request.form.get("next_steps", "").strip()
        upload = request.files.get("attachment")

        if not summary and not has_upload(upload):
            flash("Add session material text or upload a file before saving.", "error")
        else:
            session_id = add_session_for_client(
                client["id"],
                session_date,
                title,
                summary,
                "",
                next_steps,
                "therapist",
            )
            save_session_attachment(client["id"], session_id, upload, "therapist")
            flash("Session material saved for the client portal.", "success")
        return redirect(url_for("admin_client_detail", client_id=client_id))

    @app.route("/admin/clients/<int:client_id>/skills/<int:skill_id>/reflections", methods=["POST"])
    @admin_required
    def admin_add_skill_reflection(client_id: int, skill_id: int):
        client = get_client_or_404(client_id)
        skill = query_one(
            "select id from client_skills where id = ? and client_id = ?",
            (skill_id, client["id"]),
        )
        if skill is None:
            abort(404)

        reflection_text = request.form.get("reflection_text", "").strip()
        practiced_at = request.form.get("practiced_at", "").strip() or datetime.now().date().isoformat()
        if not reflection_text:
            flash("Write a therapist plan or feedback note before saving.", "error")
        else:
            add_skill_reflection_for_client(
                client["id"],
                skill_id,
                reflection_text,
                practiced_at,
                "therapist",
            )
            record_audit(client["id"], "skill_reflection_added", "Therapist added skill plan or feedback")
            flash("Therapist plan or feedback saved.", "success")
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
        active_goal = get_active_change_goal(g.client["id"])
        todays_checkin = (
            get_checkin_for_date(active_goal["id"], datetime.now().date().isoformat())
            if active_goal
            else None
        )
        return render_template(
            "dashboard.html",
            active_goal=active_goal,
            todays_checkin=todays_checkin,
            goal_summary=get_goal_summary(active_goal["id"]) if active_goal else None,
        )

    @app.route("/today/check-in", methods=["POST"])
    @login_required
    def save_today_checkin():
        active_goal = get_active_change_goal(g.client["id"])
        if active_goal is None:
            flash("Your therapist needs to set an active behaviour goal first.", "error")
            return redirect(url_for("dashboard"))

        completed_status = request.form.get("completed_status", "not_yet").strip()
        if completed_status not in {"yes", "not_yet", "skipped"}:
            completed_status = "not_yet"
        mood_rating = parse_positive_int(request.form.get("mood_rating"), default=0, maximum=5)
        note = request.form.get("note", "").strip()
        barrier_tags = request.form.getlist("barrier_tags")
        helped_tags = request.form.getlist("helped_tags")
        save_daily_checkin(
            g.client["id"],
            active_goal["id"],
            datetime.now().date().isoformat(),
            completed_status,
            mood_rating,
            note,
            barrier_tags,
            helped_tags,
        )
        record_audit(g.client["id"], "daily_checkin_saved", f"Saved check-in: {completed_status}")
        flash("Today saved.", "success")
        if request.form.get("return_to") == "track":
            return redirect(url_for("track"))
        return redirect(url_for("dashboard"))

    @app.route("/goals")
    @login_required
    def goals():
        active_goal = get_active_change_goal(g.client["id"])
        return render_template("goals.html", active_goal=active_goal)

    @app.route("/track")
    @login_required
    def track():
        active_goal = get_active_change_goal(g.client["id"])
        todays_checkin = None
        if active_goal:
            checkin = get_checkin_for_date(active_goal["id"], datetime.now().date().isoformat())
            todays_checkin = hydrate_checkin(checkin) if checkin else None
        return render_template(
            "track.html",
            active_goal=active_goal,
            todays_checkin=todays_checkin,
            week_days=get_current_week_checkins(active_goal["id"]) if active_goal else [],
            goal_summary=get_goal_summary(active_goal["id"]) if active_goal else None,
            barrier_tags=BARRIER_TAGS,
            helped_tags=HELPED_TAGS,
        )

    @app.route("/insights")
    @login_required
    def insights():
        active_goal = get_active_change_goal(g.client["id"])
        return render_template(
            "insights.html",
            active_goal=active_goal,
            goal_summary=get_goal_summary(active_goal["id"]) if active_goal else None,
            latest_review=get_latest_change_loop_review(g.client["id"]),
        )

    @app.route("/support")
    @login_required
    def support():
        active_goal = get_active_change_goal(g.client["id"])
        return render_template(
            "support.html",
            active_goal=active_goal,
            skills=get_client_skills_with_latest_reflection(g.client["id"]),
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
                        (client_id, title, category, notes, practiced_at, author_role, created_at)
                    values (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        g.client["id"],
                        title,
                        category or "Strategy",
                        notes,
                        practiced_at or datetime.now().date().isoformat(),
                        "client",
                        now_iso(),
                    ),
                )
                record_audit(g.client["id"], "skill_added", f"Added skill: {title}")
                flash("Skill saved.", "success")
                return redirect(url_for("skills"))

        return render_template("skills.html", skills=get_client_skills_with_latest_reflection(g.client["id"]))

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
            flash("Write a plan or feedback note before saving.", "error")
        else:
            add_skill_reflection_for_client(
                g.client["id"],
                skill_id,
                reflection_text,
                practiced_at,
                "client",
            )
            record_audit(g.client["id"], "skill_reflection_added", "Client added skill plan or feedback")
            flash("Plan or feedback saved.", "success")
        return redirect(get_safe_next_url() or url_for("skills"))

    @app.route("/sessions")
    @login_required
    def sessions():
        session_list = get_session_materials(g.client["id"])
        return render_template("sessions.html", sessions=session_list)

    @app.route("/sessions/material", methods=["POST"])
    @login_required
    def add_session_material():
        session_date = request.form.get("session_date", "").strip() or datetime.now().date().isoformat()
        title = request.form.get("title", "").strip() or "Session material"
        summary = request.form.get("summary", "").strip()
        upload = request.files.get("attachment")

        if not summary and not has_upload(upload):
            flash("Add session material text or upload a file before saving.", "error")
        else:
            session_id = add_session_for_client(
                g.client["id"],
                session_date,
                title,
                summary,
                "",
                "",
                "client",
            )
            save_session_attachment(g.client["id"], session_id, upload, "client")
            flash("Session material saved.", "success")
        return redirect(url_for("sessions"))

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

    @app.route("/session-attachments/<int:attachment_id>")
    def download_session_attachment(attachment_id: int):
        attachment = query_one(
            """
            select sa.*, ts.client_id as owner_client_id
            from session_attachments sa
            join therapy_sessions ts on ts.id = sa.session_id
            where sa.id = ?
            """,
            (attachment_id,),
        )
        if attachment is None:
            abort(404)
        if g.admin is None and (g.client is None or int(attachment["owner_client_id"]) != int(g.client["id"])):
            abort(404)

        upload_root = Path(current_app_config("SESSION_UPLOAD_FOLDER")).resolve()
        stored_path = Path(str(attachment["stored_path"]))
        safe_path = (upload_root / stored_path).resolve()
        if upload_root not in safe_path.parents and safe_path != upload_root:
            abort(404)
        return send_from_directory(
            safe_path.parent,
            safe_path.name,
            as_attachment=True,
            download_name=attachment["original_filename"],
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
            next_path = request.full_path if request.query_string else request.path
            return redirect(url_for("login", next=next_path))
        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.admin is None:
            return redirect(url_for("admin_login"))
        return view(**kwargs)

    return wrapped_view


def get_safe_next_url() -> str:
    next_url = request.form.get("next", "").strip() or request.args.get("next", "").strip()
    if next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return ""


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


def twilio_sms_configured() -> bool:
    return bool(get_setting("TWILIO_ACCOUNT_SID") and get_setting("TWILIO_AUTH_TOKEN") and get_twilio_sender())


def get_twilio_sender() -> str:
    return get_setting("TWILIO_FROM_NUMBER") or get_setting("TWILIO_MESSAGING_SERVICE_SID")


def send_twilio_sms(to_number: str, body: str) -> tuple[str, str]:
    twilio_sid = get_setting("TWILIO_ACCOUNT_SID")
    twilio_token = get_setting("TWILIO_AUTH_TOKEN")
    twilio_sender = get_twilio_sender()
    if not twilio_sid or not twilio_token or not twilio_sender:
        raise RuntimeError("Twilio credentials are missing")

    payload = {
        "To": to_number,
        "Body": body,
    }
    if twilio_sender.startswith("MG"):
        payload["MessagingServiceSid"] = twilio_sender
    else:
        payload["From"] = twilio_sender

    req = UrlRequest(
        f"https://api.twilio.com/2010-04-01/Accounts/{twilio_sid}/Messages.json",
        data=urlencode(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": "Basic "
            + base64.b64encode(f"{twilio_sid}:{twilio_token}".encode("utf-8")).decode("ascii"),
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Twilio request failed: HTTP {exc.code} {response_body}") from exc

    return twilio_sender, str(data.get("sid", ""))


def normalize_phone_number(phone_number: str) -> str:
    raw_value = str(phone_number or "").strip()
    digits = re.sub(r"\D+", "", raw_value)
    if not digits:
        return ""
    if raw_value.startswith("+"):
        return "+" + digits
    if digits.startswith("61") and len(digits) == 11:
        return "+" + digits
    if digits.startswith("04") and len(digits) == 10:
        return "+61" + digits[1:]
    if digits.startswith("4") and len(digits) == 9:
        return "+61" + digits
    return digits


def create_portal_invite(full_name: str, email: str, phone: str) -> str:
    token = secrets.token_urlsafe(32)
    execute(
        """
        insert into portal_invites
            (token_hash, full_name, email, phone, expires_at, created_at, used_at, used_client_id)
        values (?, ?, ?, ?, ?, ?, null, null)
        """,
        (
            hash_reset_token(token),
            full_name,
            email,
            phone,
            "9999-12-31T23:59:59+00:00",
            now_iso(),
        ),
    )
    return token


def get_valid_portal_invite(token: str) -> sqlite3.Row | None:
    if not token:
        return None
    return query_one(
        """
        select id, full_name, email, phone, expires_at
        from portal_invites
        where token_hash = ? and used_at is null
        """,
        (hash_reset_token(token),),
    )


def get_used_portal_invite(token: str) -> sqlite3.Row | None:
    if not token:
        return None
    return query_one(
        """
        select id, used_client_id
        from portal_invites
        where token_hash = ? and used_at is not null
        """,
        (hash_reset_token(token),),
    )


def mark_portal_invite_used(invite_id: int, client_id: int) -> None:
    execute(
        "update portal_invites set used_at = ?, used_client_id = ? where id = ?",
        (now_iso(), client_id, invite_id),
    )


def invite_context(invite: sqlite3.Row | None, token: str) -> dict[str, str]:
    if invite is None:
        return {"full_name": "", "email": "", "phone": "", "token": ""}
    return {
        "full_name": str(invite["full_name"] or ""),
        "email": str(invite["email"] or ""),
        "phone": str(invite["phone"] or ""),
        "token": token,
    }


def build_create_account_url(invite_token: str) -> str:
    base_url = get_setting("PORTAL_BASE_URL").rstrip("/")
    params = {"invite": invite_token}
    if base_url:
        path = url_for("create_account")
        return f"{base_url}{path}?{urlencode(params)}"
    return url_for("create_account", _external=True, **params)


def build_portal_invite_sms(full_name: str, invite_url: str) -> str:
    greeting_name = first_name(full_name) or "there"
    return (
        f"Hi {greeting_name}, Travis from TMG Psychology has set up your Engineered Psychology "
        f"client portal. Create your profile here: {invite_url}"
    )


def get_portal_reminder_schedule(client_id: int) -> sqlite3.Row | None:
    return query_one(
        """
        select *
        from portal_sms_reminder_schedules
        where client_id = ?
        """,
        (client_id,),
    )


def save_portal_reminder_schedule(
    client_id: int,
    enabled: bool,
    frequency_days: int,
    send_time_local: str,
    target_path: str,
    message_template: str,
) -> None:
    existing = get_portal_reminder_schedule(client_id)
    timezone_name = get_setting("PORTAL_REMINDER_TIMEZONE", DEFAULT_TIMEZONE)
    next_send_at = calculate_next_reminder_send_at(frequency_days, send_time_local, timezone_name)
    template = message_template or DEFAULT_REMINDER_MESSAGE
    enabled_value = 1 if enabled else 0

    if existing is None:
        execute(
            """
            insert into portal_sms_reminder_schedules
                (client_id, enabled, frequency_days, send_time_local, timezone_name, target_path,
                 message_template, last_sent_at, next_send_at, created_at, updated_at)
            values (?, ?, ?, ?, ?, ?, ?, null, ?, ?, ?)
            """,
            (
                client_id,
                enabled_value,
                frequency_days,
                send_time_local,
                timezone_name,
                target_path,
                template,
                next_send_at,
                now_iso(),
                now_iso(),
            ),
        )
        return

    execute(
        """
        update portal_sms_reminder_schedules
        set enabled = ?,
            frequency_days = ?,
            send_time_local = ?,
            timezone_name = ?,
            target_path = ?,
            message_template = ?,
            next_send_at = ?,
            updated_at = ?
        where client_id = ?
        """,
        (
            enabled_value,
            frequency_days,
            send_time_local,
            timezone_name,
            target_path,
            template,
            next_send_at,
            now_iso(),
            client_id,
        ),
    )


def dispatch_due_portal_reminders() -> dict[str, int | list[str]]:
    due_rows = query_all(
        """
        select
            prs.*,
            c.full_name,
            c.preferred_name,
            c.phone
        from portal_sms_reminder_schedules prs
        join clients c on c.id = prs.client_id
        where prs.enabled = 1
          and prs.next_send_at <= ?
        order by prs.next_send_at
        """,
        (now_iso(),),
    )
    sent = 0
    skipped = 0
    errors = []

    for row in due_rows:
        client_name = str(row["preferred_name"] or row["full_name"] or "there")
        to_number = normalize_phone_number(row["phone"])
        if not to_number:
            skipped += 1
            errors.append(f"{row['full_name']}: missing mobile number")
            continue

        link = build_portal_absolute_url(str(row["target_path"] or "/dashboard"))
        message = format_reminder_message(str(row["message_template"] or ""), client_name, link)
        try:
            _from_number, message_sid = send_twilio_sms(to_number, message)
        except Exception as exc:
            skipped += 1
            errors.append(f"{row['full_name']}: {exc}")
            continue

        next_send_at = calculate_next_reminder_send_at(
            int(row["frequency_days"] or 1),
            str(row["send_time_local"] or "09:00"),
            str(row["timezone_name"] or DEFAULT_TIMEZONE),
            from_utc=datetime.now(timezone.utc) + timedelta(seconds=1),
        )
        execute(
            """
            update portal_sms_reminder_schedules
            set last_sent_at = ?,
                next_send_at = ?,
                updated_at = ?
            where id = ?
            """,
            (now_iso(), next_send_at, now_iso(), row["id"]),
        )
        record_audit(row["client_id"], "portal_reminder_sms_sent", f"Sent portal reminder SMS: {message_sid}")
        sent += 1

    return {"due": len(due_rows), "sent": sent, "skipped": skipped, "errors": errors}


def calculate_next_reminder_send_at(
    frequency_days: int,
    send_time_local: str,
    timezone_name: str,
    from_utc: datetime | None = None,
) -> str:
    tz = ZoneInfo(timezone_name or DEFAULT_TIMEZONE)
    now_local = (from_utc or datetime.now(timezone.utc)).astimezone(tz)
    hour, minute = parse_local_time(send_time_local)
    candidate = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= now_local:
        candidate = candidate + timedelta(days=max(1, frequency_days))
    return candidate.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_local_time(value: str) -> tuple[int, int]:
    if not valid_local_time(value):
        return 9, 0
    hour_text, minute_text = value.split(":", 1)
    return int(hour_text), int(minute_text)


def valid_local_time(value: str) -> bool:
    if not re.fullmatch(r"\d{2}:\d{2}", str(value or "")):
        return False
    hour_text, minute_text = value.split(":", 1)
    hour = int(hour_text)
    minute = int(minute_text)
    return 0 <= hour <= 23 and 0 <= minute <= 59


def parse_positive_int(value: str | None, default: int = 1, maximum: int = 30) -> int:
    try:
        parsed = int(str(value or "").strip())
    except ValueError:
        return default
    return max(1, min(parsed, maximum))


def build_portal_absolute_url(path: str) -> str:
    clean_path = path if path.startswith("/") and not path.startswith("//") else "/dashboard"
    base_url = get_setting("PORTAL_BASE_URL", "https://portal.engineeredpsychology.com").rstrip("/")
    return f"{base_url}{clean_path}"


def format_reminder_message(template: str, client_name: str, link: str) -> str:
    first = first_name(client_name) or "there"
    body = template or DEFAULT_REMINDER_MESSAGE
    try:
        return body.format(first_name=first, full_name=client_name, link=link)
    except (KeyError, ValueError):
        return DEFAULT_REMINDER_MESSAGE.format(first_name=first, full_name=client_name, link=link)


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
    for env_name in (
        "PORTAL_EXTRA_ENV_FILE",
        "TWILIO_ENV_FILE",
        "GRAPH_ENV_FILE",
        "MICROSOFT_GRAPH_ENV_FILE",
    ):
        configured = os.environ.get(env_name, "").strip()
        if configured:
            paths.append(Path(configured).expanduser())
    paths.append(BASE_DIR / ".env")
    paths.append(BASE_DIR.parent / "admin.engineeredpsychology repo" / "admin-tools" / ".env")
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
    author_role: str = "therapist",
) -> None:
    execute(
        """
        insert into client_skills (client_id, title, category, notes, practiced_at, author_role, created_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (client_id, title, category, notes, practiced_at, author_role, now_iso()),
    )
    record_audit(client_id, "skill_added", f"Added skill: {title}")


def add_skill_reflection_for_client(
    client_id: int,
    skill_id: int,
    reflection_text: str,
    practiced_at: str,
    author_role: str,
) -> None:
    execute(
        """
        insert into client_skill_reflections
            (client_id, skill_id, reflection_text, practiced_at, author_role, created_at)
        values (?, ?, ?, ?, ?, ?)
        """,
        (client_id, skill_id, reflection_text, practiced_at, author_role, now_iso()),
    )


def save_change_goal(
    client_id: int,
    focus_area: str,
    values_link: str,
    behaviour_target: str,
    tiny_behaviour: str,
    cue: str,
    backup_version: str,
    frequency_target: int,
    confidence_rating: int,
) -> None:
    execute("update change_goals set status = 'inactive' where client_id = ? and status = 'active'", (client_id,))
    execute(
        """
        insert into change_goals
            (client_id, focus_area, values_link, behaviour_target, tiny_behaviour, cue,
             backup_version, frequency_target, confidence_rating, status, created_at, updated_at)
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
        """,
        (
            client_id,
            focus_area,
            values_link,
            behaviour_target,
            tiny_behaviour,
            cue,
            backup_version,
            frequency_target,
            confidence_rating,
            now_iso(),
            now_iso(),
        ),
    )
    record_audit(client_id, "change_goal_saved", f"Active behaviour goal saved: {behaviour_target}")


def get_active_change_goal(client_id: int) -> sqlite3.Row | None:
    return query_one(
        """
        select *
        from change_goals
        where client_id = ? and status = 'active'
        order by created_at desc
        limit 1
        """,
        (client_id,),
    )


def get_checkin_for_date(goal_id: int, checkin_date: str) -> sqlite3.Row | None:
    return query_one(
        """
        select *
        from daily_checkins
        where goal_id = ? and checkin_date = ?
        """,
        (goal_id, checkin_date),
    )


def save_daily_checkin(
    client_id: int,
    goal_id: int,
    checkin_date: str,
    completed_status: str,
    mood_rating: int,
    note: str,
    barrier_tags: list[str],
    helped_tags: list[str],
) -> None:
    existing = get_checkin_for_date(goal_id, checkin_date)
    clean_barriers = [tag for tag in barrier_tags if tag in BARRIER_TAGS]
    clean_helped = [tag for tag in helped_tags if tag in HELPED_TAGS]
    if existing is None:
        execute(
            """
            insert into daily_checkins
                (client_id, goal_id, checkin_date, completed_status, mood_rating, note,
                 barrier_tags, helped_tags, created_at, updated_at)
            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id,
                goal_id,
                checkin_date,
                completed_status,
                mood_rating,
                note,
                json.dumps(clean_barriers),
                json.dumps(clean_helped),
                now_iso(),
                now_iso(),
            ),
        )
        return

    execute(
        """
        update daily_checkins
        set completed_status = ?,
            mood_rating = ?,
            note = ?,
            barrier_tags = ?,
            helped_tags = ?,
            updated_at = ?
        where id = ?
        """,
        (
            completed_status,
            mood_rating,
            note,
            json.dumps(clean_barriers),
            json.dumps(clean_helped),
            now_iso(),
            existing["id"],
        ),
    )


def get_recent_goal_checkins(goal_id: int, limit: int = 14) -> list[dict]:
    rows = query_all(
        """
        select *
        from daily_checkins
        where goal_id = ?
        order by checkin_date desc
        limit ?
        """,
        (goal_id, limit),
    )
    return [hydrate_checkin(row) for row in rows]


def get_current_week_checkins(goal_id: int) -> list[dict]:
    today = datetime.now().date()
    start = today - timedelta(days=today.weekday())
    rows = query_all(
        """
        select *
        from daily_checkins
        where goal_id = ? and checkin_date >= ? and checkin_date <= ?
        """,
        (goal_id, start.isoformat(), (start + timedelta(days=6)).isoformat()),
    )
    by_date = {row["checkin_date"]: hydrate_checkin(row) for row in rows}
    days = []
    for offset in range(7):
        day = start + timedelta(days=offset)
        checkin = by_date.get(day.isoformat())
        days.append(
            {
                "date": day.isoformat(),
                "label": day.strftime("%a"),
                "status": checkin["completed_status"] if checkin else "open",
                "mood_rating": checkin["mood_rating"] if checkin else None,
            }
        )
    return days


def get_goal_summary(goal_id: int) -> dict:
    today = datetime.now().date()
    this_start = today - timedelta(days=6)
    last_start = today - timedelta(days=13)
    last_end = today - timedelta(days=7)
    this_rows = get_checkins_between(goal_id, this_start.isoformat(), today.isoformat())
    last_rows = get_checkins_between(goal_id, last_start.isoformat(), last_end.isoformat())
    completed_count = count_completed(this_rows)
    last_completed = count_completed(last_rows)
    mood_average = average_rating(this_rows, "mood_rating")
    last_mood_average = average_rating(last_rows, "mood_rating")
    common_barrier = most_common_tag(this_rows, "barrier_tags") or "Not enough data yet"
    common_help = most_common_tag(this_rows, "helped_tags") or "Not enough data yet"
    return {
        "completed_count": completed_count,
        "last_completed_count": last_completed,
        "practice_delta": completed_count - last_completed,
        "checkin_count": len(this_rows),
        "mood_average": mood_average,
        "mood_delta": round(mood_average - last_mood_average, 1) if mood_average and last_mood_average else None,
        "common_barrier": common_barrier,
        "common_help": common_help,
    }


def get_checkins_between(goal_id: int, start_date: str, end_date: str) -> list[dict]:
    rows = query_all(
        """
        select *
        from daily_checkins
        where goal_id = ? and checkin_date >= ? and checkin_date <= ?
        order by checkin_date
        """,
        (goal_id, start_date, end_date),
    )
    return [hydrate_checkin(row) for row in rows]


def hydrate_checkin(row: sqlite3.Row) -> dict:
    checkin = dict(row)
    checkin["barrier_tags"] = parse_json_list(checkin.get("barrier_tags"))
    checkin["helped_tags"] = parse_json_list(checkin.get("helped_tags"))
    return checkin


def parse_json_list(value: str | None) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def count_completed(rows: list[dict]) -> int:
    return sum(1 for row in rows if row.get("completed_status") == "yes")


def average_rating(rows: list[dict], key: str) -> float:
    ratings = [int(row[key]) for row in rows if row.get(key)]
    if not ratings:
        return 0
    return round(sum(ratings) / len(ratings), 1)


def most_common_tag(rows: list[dict], key: str) -> str:
    counts: dict[str, int] = {}
    for row in rows:
        for tag in row.get(key, []):
            counts[tag] = counts.get(tag, 0) + 1
    if not counts:
        return ""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


def get_latest_change_loop_review(client_id: int) -> dict | None:
    row = query_one(
        """
        select *
        from therapist_reviews
        where client_id = ?
        order by created_at desc
        limit 1
        """,
        (client_id,),
    )
    if row is None:
        return None
    review = dict(row)
    review["breakdown_points"] = parse_json_list(review.get("breakdown_points"))
    return review


def get_client_skills_with_latest_reflection(client_id: int) -> list[dict]:
    skill_rows = query_all(
        """
        select id, title, category, notes, practiced_at, author_role, created_at
        from client_skills cs
        where cs.client_id = ?
        order by cs.practiced_at desc, cs.created_at desc
        """,
        (client_id,),
    )
    reflection_rows = query_all(
        """
        select id, skill_id, reflection_text, practiced_at, author_role, created_at
        from client_skill_reflections
        where client_id = ?
        order by practiced_at desc, created_at desc
        """,
        (client_id,),
    )
    reflections_by_skill: dict[int, list[dict]] = {}
    for row in reflection_rows:
        reflections_by_skill.setdefault(int(row["skill_id"]), []).append(dict(row))

    skills = []
    for row in skill_rows:
        skill = dict(row)
        skill["reflections"] = reflections_by_skill.get(int(row["id"]), [])
        skills.append(skill)
    return skills


def get_session_materials(client_id: int) -> list[dict]:
    session_rows = query_all(
        """
        select
            ts.id,
            ts.session_date,
            ts.title,
            ts.summary,
            ts.key_skills,
            ts.next_steps,
            ts.author_role,
            ts.created_at,
            latest_reflection.reflection_text,
            latest_reflection.created_at as reflection_created_at,
            latest_reflection.reflection_text as client_reflection,
            latest_reflection.created_at as client_reflection_created_at
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
        (client_id, client_id, client_id),
    )
    sessions = [dict(row) for row in session_rows]
    if not sessions:
        return []

    placeholders = ",".join("?" for _row in sessions)
    attachment_rows = query_all(
        f"""
        select id, session_id, original_filename, content_type, file_size, uploader_role, created_at
        from session_attachments
        where session_id in ({placeholders})
        order by created_at
        """,
        tuple(session["id"] for session in sessions),
    )
    attachments_by_session: dict[int, list[dict]] = {}
    for row in attachment_rows:
        attachment = dict(row)
        attachment["file_size_label"] = format_file_size(int(attachment.get("file_size") or 0))
        attachments_by_session.setdefault(int(row["session_id"]), []).append(attachment)

    for session in sessions:
        session["attachments"] = attachments_by_session.get(int(session["id"]), [])
    return sessions


def add_session_for_client(
    client_id: int,
    session_date: str,
    title: str,
    summary: str,
    key_skills: str,
    next_steps: str,
    author_role: str = "therapist",
) -> int:
    db = get_db()
    cursor = db.execute(
        """
        insert into therapy_sessions
            (client_id, session_date, title, summary, key_skills, next_steps, author_role, created_at)
        values (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (client_id, session_date, title, summary, key_skills, next_steps, author_role, now_iso()),
    )
    db.commit()
    session_id = int(cursor.lastrowid)
    if author_role == "therapist":
        for skill in parse_skill_lines(key_skills):
            add_skill_for_client(
                client_id,
                skill,
                "Session skill",
                f"Added from session: {title}",
                session_date,
            )
    record_audit(client_id, "session_added", f"Added session: {title}")
    return session_id


def has_upload(upload) -> bool:
    return bool(upload and upload.filename)


def save_session_attachment(client_id: int, session_id: int, upload, uploader_role: str) -> None:
    if not has_upload(upload):
        return

    original_filename = secure_filename(upload.filename or "")
    if not original_filename:
        return

    upload_root = Path(current_app_config("SESSION_UPLOAD_FOLDER")).resolve()
    relative_dir = Path(str(client_id)) / str(session_id)
    target_dir = upload_root / relative_dir
    target_dir.mkdir(parents=True, exist_ok=True)

    stored_filename = f"{secrets.token_hex(12)}-{original_filename}"
    upload.save(target_dir / stored_filename)
    stored_path = str(relative_dir / stored_filename)
    file_size = (target_dir / stored_filename).stat().st_size
    execute(
        """
        insert into session_attachments
            (client_id, session_id, uploader_role, original_filename, stored_path, content_type, file_size, created_at)
        values (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            client_id,
            session_id,
            uploader_role,
            original_filename,
            stored_path,
            upload.mimetype or "application/octet-stream",
            file_size,
            now_iso(),
        ),
    )
    record_audit(client_id, "session_attachment_added", f"Uploaded session file: {original_filename}")


def format_file_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{round(size_bytes / 1024, 1)} KB"
    return f"{round(size_bytes / (1024 * 1024), 1)} MB"


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
                author_role text not null default 'therapist',
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
                author_role text not null default 'therapist',
                created_at text not null
            );

            create table if not exists session_attachments (
                id integer primary key autoincrement,
                client_id integer not null references clients(id),
                session_id integer not null references therapy_sessions(id),
                uploader_role text not null default 'therapist',
                original_filename text not null,
                stored_path text not null,
                content_type text,
                file_size integer not null default 0,
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
                author_role text not null default 'client',
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

            create table if not exists portal_invites (
                id integer primary key autoincrement,
                token_hash text not null unique,
                full_name text,
                email text,
                phone text,
                expires_at text not null,
                created_at text not null,
                used_at text,
                used_client_id integer references clients(id)
            );

            create table if not exists portal_sms_reminder_schedules (
                id integer primary key autoincrement,
                client_id integer not null unique references clients(id),
                enabled integer not null default 0,
                frequency_days integer not null default 1,
                send_time_local text not null default '09:00',
                timezone_name text not null default 'Australia/Sydney',
                target_path text not null default '/sessions',
                message_template text not null,
                last_sent_at text,
                next_send_at text not null,
                created_at text not null,
                updated_at text not null
            );

            create table if not exists change_goals (
                id integer primary key autoincrement,
                client_id integer not null references clients(id),
                focus_area text not null,
                values_link text,
                behaviour_target text not null,
                tiny_behaviour text not null,
                cue text not null,
                backup_version text,
                frequency_target integer not null default 5,
                confidence_rating integer not null default 7,
                status text not null default 'active',
                created_at text not null,
                updated_at text not null
            );

            create table if not exists daily_checkins (
                id integer primary key autoincrement,
                client_id integer not null references clients(id),
                goal_id integer not null references change_goals(id),
                checkin_date text not null,
                completed_status text not null,
                mood_rating integer,
                note text,
                barrier_tags text not null default '[]',
                helped_tags text not null default '[]',
                created_at text not null,
                updated_at text not null,
                unique(goal_id, checkin_date)
            );

            create table if not exists therapist_reviews (
                id integer primary key autoincrement,
                client_id integer not null references clients(id),
                goal_id integer not null references change_goals(id),
                review_date text not null,
                breakdown_points text not null default '[]',
                recommended_adjustment text,
                session_agenda text,
                created_at text not null
            );

            create index if not exists idx_password_reset_tokens_client
                on password_reset_tokens(client_id);
            create index if not exists idx_password_reset_tokens_token_hash
                on password_reset_tokens(token_hash);
            create index if not exists idx_portal_invites_token_hash
                on portal_invites(token_hash);
            create index if not exists idx_portal_sms_reminders_next_send
                on portal_sms_reminder_schedules(enabled, next_send_at);
            create index if not exists idx_session_reflections_session
                on session_reflections(session_id);
            create index if not exists idx_session_attachments_session
                on session_attachments(session_id);
            create index if not exists idx_client_skill_reflections_skill
                on client_skill_reflections(skill_id);
            create index if not exists idx_change_goals_client_status
                on change_goals(client_id, status);
            create index if not exists idx_daily_checkins_goal_date
                on daily_checkins(goal_id, checkin_date);
            create index if not exists idx_therapist_reviews_client
                on therapist_reviews(client_id, created_at);
            """
        )
        ensure_column_exists(db, "therapy_sessions", "author_role", "text not null default 'therapist'")
        ensure_column_exists(db, "client_skills", "author_role", "text not null default 'therapist'")
        ensure_column_exists(db, "client_skill_reflections", "author_role", "text not null default 'client'")
        db.commit()
        seed_demo_data()
        ensure_demo_session_data()
        ensure_demo_change_loop_data()
        ensure_master_account()


def ensure_column_exists(db: sqlite3.Connection, table_name: str, column_name: str, definition: str) -> None:
    columns = {row["name"] for row in db.execute(f"pragma table_info({table_name})").fetchall()}
    if column_name not in columns:
        db.execute(f"alter table {table_name} add column {column_name} {definition}")


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
        insert into client_skills (client_id, title, category, notes, practiced_at, author_role, created_at)
        values (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            client_id,
            "Grounding practice",
            "Regulation",
            "Notice five things you can see, four you can feel, three you can hear, two you can smell, and one you can taste.",
            datetime.now().date().isoformat(),
            "therapist",
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


def ensure_demo_change_loop_data() -> None:
    client = query_one("select id from clients order by id limit 1")
    if client is None:
        return

    existing = query_one("select id from change_goals where client_id = ? limit 1", (client["id"],))
    if existing is not None:
        return

    save_change_goal(
        int(client["id"]),
        "Anxiety and avoidance",
        "I want to feel more capable and less controlled by avoidance.",
        "Open avoided emails after morning coffee",
        "Open the inbox and read one email only.",
        "After making morning coffee",
        "Open the inbox for 30 seconds only.",
        5,
        8,
    )
    goal = get_active_change_goal(int(client["id"]))
    if goal is None:
        return

    today = datetime.now().date()
    demo_rows = [
        (-6, "yes", 3, "It was easier once I started.", [], ["Reminder"]),
        (-5, "yes", 3, "Read one low-stakes email.", [], ["Smaller task"]),
        (-4, "skipped", 2, "I avoided emails from my boss.", ["Anxious"], []),
        (-3, "yes", 4, "Coffee cue helped.", [], ["Values reminder"]),
        (-2, "not_yet", 3, "", ["No time"], []),
        (-1, "yes", 4, "Opened inbox for two minutes.", [], ["Reminder"]),
    ]
    for offset, status, mood, note, barriers, helped in demo_rows:
        save_daily_checkin(
            int(client["id"]),
            int(goal["id"]),
            (today + timedelta(days=offset)).isoformat(),
            status,
            mood,
            note,
            barriers,
            helped,
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
    if len(sys.argv) > 1 and sys.argv[1] == "dispatch-reminders":
        with app.app_context():
            print(json.dumps(dispatch_due_portal_reminders()))
    else:
        host = os.environ.get("HOST", "127.0.0.1")
        port = int(os.environ.get("PORT", "3020"))
        app.run(host=host, port=port, debug=os.environ.get("FLASK_ENV") == "development")

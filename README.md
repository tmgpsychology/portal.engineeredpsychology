# Engineered Psychology Client Portal

Standalone client-facing portal for `portal.engineeredpsychology.com`.

This project is intentionally separate from the internal admin app. It starts with:

- client login with hashed passwords
- mobile-friendly client dashboard
- profile details
- session cards
- skills and interventions attached to sessions
- SQLite storage for the first deployment phase

## Local Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Open `http://127.0.0.1:3020`.

## Default Login

The app seeds a local demo client if the database is empty:

- Email: `client@example.com`
- Password: `change-me-now`

Change this before production use.

## Deployment Shape

Recommended EC2 layout:

```text
/home/ec2-user/apps/portal-engineeredpsychology
```

Recommended local port: `3020`.

Use the files in `deploy/` as the starting point for systemd and nginx.

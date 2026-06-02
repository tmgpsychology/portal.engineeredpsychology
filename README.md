# Engineered Psychology Client Portal

Standalone client-facing portal for `portal.engineeredpsychology.com`.

This project is intentionally separate from the internal admin app. It starts with:

- client login with hashed passwords
- password reset emails from TMG Psychology
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

## Password Reset Email

Password reset links can be sent through Microsoft Graph. Configure these in `.env`:

```bash
MAIL_PROVIDER=graph
MS_TENANT_ID=replace-with-tenant-id
MS_CLIENT_ID=replace-with-client-id
MS_CLIENT_SECRET=replace-with-client-secret
OUTLOOK_EMAIL_ADDRESS=portal@example.com
MAIL_FROM_NAME=TMG Psychology
PASSWORD_RESET_EXPIRY_MINUTES=60
```

If the server already has these values in the admin tools environment, point the portal at that file instead:

```bash
MAIL_PROVIDER=graph
GRAPH_ENV_FILE=/home/ec2-user/apps/admin-tools/.env
OUTLOOK_EMAIL_ADDRESS=portal@example.com
MAIL_FROM_NAME=TMG Psychology
PASSWORD_RESET_EXPIRY_MINUTES=60
```

SMTP is still supported as a fallback:

```bash
MAIL_PROVIDER=smtp
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=portal@example.com
SMTP_PASSWORD=replace-with-smtp-password
SMTP_USE_TLS=true
SMTP_USE_SSL=false
MAIL_FROM=portal@example.com
MAIL_FROM_NAME=TMG Psychology
PASSWORD_RESET_EXPIRY_MINUTES=60
```

## Therapist Accounts

The first therapist/admin account is seeded from `MASTER_EMAIL`, `MASTER_PASSWORD`, and `MASTER_NAME`.
After one therapist account exists, public creation of extra therapist accounts is locked unless
`THERAPIST_SIGNUP_CODE` is configured.

## Portal SMS Invites

Therapists can send a client an SMS link to create their portal profile. Configure Twilio in `.env`,
or point the portal at the admin tools environment file:

```bash
PORTAL_BASE_URL=https://portal.engineeredpsychology.com
TWILIO_ENV_FILE=/home/ec2-user/apps/admin-tools/.env
TWILIO_ACCOUNT_SID=replace-with-account-sid
TWILIO_AUTH_TOKEN=replace-with-auth-token
TWILIO_FROM_NUMBER=replace-with-twilio-number
```

`TWILIO_MESSAGING_SERVICE_SID` can be used instead of `TWILIO_FROM_NUMBER`.

## Deployment Shape

Recommended EC2 layout:

```text
/home/ec2-user/apps/portal-engineeredpsychology
```

Recommended local port: `3020`.

Use the files in `deploy/` as the starting point for systemd and nginx.

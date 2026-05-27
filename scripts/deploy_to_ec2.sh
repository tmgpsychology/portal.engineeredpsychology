#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <ec2-host> [ec2-user]"
  echo "Example: $0 100.53.132.84 ec2-user"
  exit 1
fi

EC2_HOST="$1"
EC2_USER="${2:-ec2-user}"
SSH_TARGET="${EC2_USER}@${EC2_HOST}"
SSH_KEY="${HOME}/.ssh/github_actions_ec2_deploy"
REMOTE_APP_DIR="/home/ec2-user/apps/portal-engineeredpsychology"
SERVICE_NAME="portal-engineeredpsychology"
SSH_OPTS=(
  -i "${SSH_KEY}"
  -o BatchMode=yes
  -o ConnectTimeout=10
  -o ConnectionAttempts=3
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=3
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Preparing ${REMOTE_APP_DIR} on ${SSH_TARGET}"
ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" "mkdir -p ${REMOTE_APP_DIR}"

echo "Deploying portal app to ${SSH_TARGET}"
rsync -av \
  --exclude ".env" \
  --exclude ".git/" \
  --exclude ".venv/" \
  --exclude "__pycache__/" \
  --exclude "*.pyc" \
  --exclude "portal.db" \
  -e "ssh ${SSH_OPTS[*]}" \
  "${REPO_ROOT}/" \
  "${SSH_TARGET}:${REMOTE_APP_DIR}/"

echo "Uploading systemd service to ${SSH_TARGET}"
rsync -av \
  -e "ssh ${SSH_OPTS[*]}" \
  "${REPO_ROOT}/deploy/portal-engineeredpsychology.service" \
  "${SSH_TARGET}:/tmp/portal-engineeredpsychology.service"

echo "Installing dependencies and restarting ${SERVICE_NAME}"
REMOTE_RESTART_CMD="cd ${REMOTE_APP_DIR} && \
python3 -m venv .venv && \
.venv/bin/pip install -r requirements.txt && \
if [ ! -f .env ]; then cp .env.example .env; fi && \
sudo mv /tmp/portal-engineeredpsychology.service /etc/systemd/system/portal-engineeredpsychology.service && \
sudo systemctl daemon-reload && \
sudo systemctl enable --now ${SERVICE_NAME} && \
sudo systemctl restart ${SERVICE_NAME} && \
sudo systemctl status ${SERVICE_NAME} --no-pager"

restart_success=0
for attempt in 1 2 3; do
  if ssh "${SSH_OPTS[@]}" "${SSH_TARGET}" "${REMOTE_RESTART_CMD}"; then
    restart_success=1
    break
  fi
  echo "Restart attempt ${attempt} failed."
  if [[ "${attempt}" -lt 3 ]]; then
    echo "Waiting 10 seconds before retrying..."
    sleep 10
  fi
done

if [[ "${restart_success}" -ne 1 ]]; then
  echo "Remote restart step failed after 3 attempts."
  exit 255
fi

echo "Deploy complete."

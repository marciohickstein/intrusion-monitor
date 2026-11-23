#!/bin/bash
# Executado pelo GitHub Actions via SSH (forced command da chave do usuario monitor).
# Instalado pelo setup.sh em /usr/local/bin/intrusion-monitor-deploy (dono root).
set -euo pipefail

APP_DIR=/opt/intrusion-monitor
SERVICE=intrusion-monitor
NODE_DIR="$(dirname "$(readlink -f /usr/local/bin/intrusion-monitor-node)")"
export PATH="$NODE_DIR:/usr/local/bin:/usr/bin:/bin"

cd "$APP_DIR"
echo ">> Atualizando codigo"
git fetch --quiet origin master
git reset --hard --quiet origin/master
echo ">> Commit $(git rev-parse --short HEAD): $(git log -1 --pretty=%s)"

echo ">> Instalando dependencias"
npm ci --omit=dev --no-audit --no-fund --loglevel=error

echo ">> Reiniciando servico"
sudo -n /usr/bin/systemctl restart "$SERVICE"

for i in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS --max-time 2 http://127.0.0.1:3100/healthz >/dev/null 2>&1; then
    echo ">> OK: servico respondendo"
    exit 0
  fi
  sleep 1
done
echo "!! Servico nao respondeu em /healthz" >&2
sudo -n /usr/bin/journalctl -u "$SERVICE" -n 30 --no-pager >&2 || true
exit 1

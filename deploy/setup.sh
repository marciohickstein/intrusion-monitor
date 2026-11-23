#!/bin/bash
# Instalacao unica do intrusion-monitor no servidor. Rodar como root:
#   sudo REPO_URL=git@github.com:USUARIO/intrusion-monitor.git DOMAIN=monitor.seudominio.com bash setup.sh
# E idempotente: pode rodar de novo (ex.: depois de cadastrar a deploy key no GitHub).
set -euo pipefail

REPO_URL="${REPO_URL:?defina REPO_URL (ex.: git@github.com:usuario/intrusion-monitor.git)}"
DOMAIN="${DOMAIN:?defina DOMAIN (ex.: monitor.seudominio.com)}"
FRONTEND_CONTAINER="${FRONTEND_CONTAINER:-hash-generator-frontend-1}"
APP_USER=monitor
APP_DIR=/opt/intrusion-monitor
ENV_FILE=/etc/intrusion-monitor.env
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "Rode como root."; exit 1; }
step() { echo; echo "==> $*"; }

step "Verificando dependencias"
for bin in git curl nginx; do command -v "$bin" >/dev/null || { echo "Falta: $bin"; exit 1; }; done
NODE_BIN="$(readlink -f "$(command -v node || true)")"
if [ -z "$NODE_BIN" ] || [[ "$NODE_BIN" == /home/* ]] || [[ "$NODE_BIN" == /root/* ]]; then
  echo "Node.js de sistema nao encontrado (nvm em /home nao serve para o servico)."
  echo "Instale: curl -fsSL https://deb.nodesource.com/setup_24.x | bash - && apt install -y nodejs"
  exit 1
fi
"$NODE_BIN" -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>20||(a===20&&b>=12)?0:1)' \
  || { echo "Node >= 20.12 necessario (atual: $("$NODE_BIN" -v))"; exit 1; }
ln -sf "$NODE_BIN" /usr/local/bin/intrusion-monitor-node
echo "node: $NODE_BIN ($("$NODE_BIN" -v))"

step "Usuario $APP_USER"
if ! id "$APP_USER" >/dev/null 2>&1; then
  useradd --create-home --shell /bin/bash "$APP_USER"
fi
passwd -l "$APP_USER" >/dev/null
# adm: ler /var/log/{ufw,fail2ban,nginx/*}.log  |  systemd-journal: ler o journal (SSH, kernel)
usermod -aG adm,systemd-journal "$APP_USER"

step "sudoers (somente os comandos exatos que o app precisa)"
cat > /etc/sudoers.d/intrusion-monitor <<SUDO
# Gerado por intrusion-monitor/deploy/setup.sh
Defaults:$APP_USER !requiretty
$APP_USER ALL=(root) NOPASSWD: /usr/bin/fail2ban-client status sshd
$APP_USER ALL=(root) NOPASSWD: /usr/bin/docker logs --since 24h --tail 20000 $FRONTEND_CONTAINER
$APP_USER ALL=(root) NOPASSWD: /usr/bin/systemctl restart intrusion-monitor
$APP_USER ALL=(root) NOPASSWD: /usr/bin/journalctl -u intrusion-monitor -n 30 --no-pager
SUDO
chmod 440 /etc/sudoers.d/intrusion-monitor
visudo -cf /etc/sudoers.d/intrusion-monitor

step "Chave para o servidor baixar o repositorio (Deploy key do GitHub)"
HOME_DIR="$(getent passwd "$APP_USER" | cut -d: -f6)"
install -d -m 700 -o "$APP_USER" -g "$APP_USER" "$HOME_DIR/.ssh"
if [ ! -f "$HOME_DIR/.ssh/id_ed25519" ]; then
  sudo -u "$APP_USER" ssh-keygen -q -t ed25519 -N "" -C "intrusion-monitor-server" -f "$HOME_DIR/.ssh/id_ed25519"
fi
sudo -u "$APP_USER" bash -c "ssh-keygen -F github.com -f ~/.ssh/known_hosts >/dev/null 2>&1 || ssh-keyscan -t ed25519 github.com >> ~/.ssh/known_hosts 2>/dev/null"

step "Chave do GitHub Actions (so consegue rodar o deploy)"
ACTIONS_KEY=/root/intrusion-monitor-actions-key
if [ ! -f "$HOME_DIR/.ssh/authorized_keys" ] || ! grep -q intrusion-monitor-deploy "$HOME_DIR/.ssh/authorized_keys"; then
  rm -f "$ACTIONS_KEY" "$ACTIONS_KEY.pub"
  ssh-keygen -q -t ed25519 -N "" -C "github-actions-intrusion-monitor" -f "$ACTIONS_KEY"
  echo "restrict,command=\"/usr/local/bin/intrusion-monitor-deploy\" $(cat "$ACTIONS_KEY.pub")" > "$HOME_DIR/.ssh/authorized_keys"
  NEW_ACTIONS_KEY=1
fi
chown root:root "$HOME_DIR/.ssh/authorized_keys"
chmod 644 "$HOME_DIR/.ssh/authorized_keys"

step "Script de deploy"
install -m 755 -o root -g root "$SRC_DIR/deploy.sh" /usr/local/bin/intrusion-monitor-deploy

step "Codigo em $APP_DIR"
if [ ! -d "$APP_DIR/.git" ]; then
  install -d -o "$APP_USER" -g "$APP_USER" "$APP_DIR"
  if ! sudo -u "$APP_USER" git clone --quiet "$REPO_URL" "$APP_DIR"; then
    echo
    echo "!! Nao consegui clonar. Cadastre esta chave como Deploy key (somente leitura) em"
    echo "   GitHub > repo > Settings > Deploy keys > Add deploy key:"
    echo
    cat "$HOME_DIR/.ssh/id_ed25519.pub"
    echo
    echo "   Depois rode este script de novo."
    exit 1
  fi
fi
(cd "$APP_DIR" && sudo -u "$APP_USER" env PATH="$(dirname "$NODE_BIN"):$PATH" npm ci --omit=dev --no-audit --no-fund --loglevel=error)

step "Configuracao $ENV_FILE"
if [ ! -f "$ENV_FILE" ]; then
  read -rp "Usuario do painel [admin]: " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-admin}"
  HASH="$(cd "$APP_DIR" && "$NODE_BIN" scripts/hash-password.js)"
  cat > "$ENV_FILE" <<CONF
NODE_ENV=production
HOST=127.0.0.1
PORT=3100
ADMIN_USER=$ADMIN_USER
ADMIN_PASSWORD_HASH='$HASH'
SESSION_SECRET=$(openssl rand -hex 32)
FRONTEND_CONTAINER=$FRONTEND_CONTAINER
SSH_SINCE=7 days ago
CONF
fi
chown root:"$APP_USER" "$ENV_FILE"
chmod 640 "$ENV_FILE"

step "Servico systemd"
install -m 644 "$SRC_DIR/intrusion-monitor.service" /etc/systemd/system/intrusion-monitor.service
systemctl daemon-reload
systemctl enable --now intrusion-monitor
systemctl restart intrusion-monitor

step "nginx ($DOMAIN)"
install -m 644 "$SRC_DIR/nginx-proxy-snippet.conf" /etc/nginx/snippets/intrusion-monitor-proxy.conf
if [ ! -f /etc/nginx/sites-available/intrusion-monitor ]; then
  sed "s/__DOMAIN__/$DOMAIN/g" "$SRC_DIR/nginx-site.conf" > /etc/nginx/sites-available/intrusion-monitor
fi
ln -sf /etc/nginx/sites-available/intrusion-monitor /etc/nginx/sites-enabled/intrusion-monitor
nginx -t
systemctl reload nginx

step "Pronto"
sleep 2
curl -fsS http://127.0.0.1:3100/healthz && echo " <- healthz"
echo
echo "Proximos passos:"
echo " 1. HTTPS (obrigatorio, o cookie de sessao so funciona em HTTPS):"
echo "      certbot --nginx -d $DOMAIN"
echo " 2. Se o sshd tiver AllowUsers, inclua: $APP_USER"
if [ "${NEW_ACTIONS_KEY:-0}" = 1 ]; then
  echo " 3. Copie a chave PRIVADA abaixo para o secret SERVER_SSH_KEY no GitHub e depois apague:"
  echo "      shred -u $ACTIONS_KEY $ACTIONS_KEY.pub"
  echo
  cat "$ACTIONS_KEY"
fi
echo
echo "Fingerprint do servidor (secret SERVER_HOST_FINGERPRINT):"
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}'

# intrusion-monitor

Painel web (Express + EJS) para acompanhar tentativas de ataque ao servidor:

1. **SSH**: falhas, usuários inválidos, desconexões pré-autenticação, logins aceitos e `last`
2. **fail2ban**: status da jail `sshd` e histórico de bans
3. **ufw**: pacotes bloqueados por origem e porta
4. **nginx**: scans suspeitos (`.env`, `wp-login`, `.git`...), erros 4xx/5xx e o rate limit (429) do hash-generator

Acesso protegido por usuário e senha (bcrypt), com sessão em cookie `HttpOnly`/`Secure`/`SameSite=Strict`, limite de 5 tentativas de login a cada 15 minutos e cabeçalhos do helmet.

## Como roda no servidor

| Item | Onde |
|---|---|
| Código | `/opt/intrusion-monitor` (usuário `monitor`) |
| Configuração | `/etc/intrusion-monitor.env` (root:monitor 640) |
| Serviço | `systemctl status intrusion-monitor` (escuta em `127.0.0.1:3100`) |
| Acesso | `https://<DOMAIN>` via nginx do host |
| Deploy | `/usr/local/bin/intrusion-monitor-deploy` (forced command da chave do Actions) |

O app roda como o usuário **`monitor`, não como root**. O usuário tem:
- os grupos `adm` (para ler `/var/log/ufw.log`, `fail2ban.log` e `nginx/*.log`) e `systemd-journal` (para ler o journal com SSH e kernel);
- sudo sem senha **apenas** para comandos exatos (ver `/etc/sudoers.d/intrusion-monitor`): `fail2ban-client status sshd`, `docker logs ... <container>` e `systemctl restart intrusion-monitor`.

Não usamos o grupo `docker`, porque ele dá acesso equivalente a root.

## Instalação (uma vez, como root)

Pré-requisitos no servidor: `git`, `curl`, `nginx`, `certbot` e Node.js ≥ 20.12 de sistema (não pode ser nvm).
Se faltar o Node: `curl -fsSL https://deb.nodesource.com/setup_24.x | bash - && apt install -y nodejs`.

```bash
# Na sua máquina: envie a pasta deploy/
scp -r deploy root@SERVIDOR:/root/intrusion-monitor-setup

# No servidor, como root
cd /root/intrusion-monitor-setup
REPO_URL=git@github.com:USUARIO/intrusion-monitor.git DOMAIN=monitor.seudominio.com bash setup.sh
```

1. Na primeira execução, o script mostra a **Deploy key**. Cadastre-a em *GitHub › repo › Settings › Deploy keys* como somente leitura e rode o script de novo.
2. Ao final, o script pede o usuário e a senha do painel (mínimo 12 caracteres), mostra a **chave privada do Actions** e o **fingerprint** do servidor.
3. Ative o HTTPS: `certbot --nginx -d monitor.seudominio.com`. Antes, crie o registro DNS `A` apontando para o droplet.
4. Se o `sshd_config` tiver `AllowUsers`, inclua `monitor`.
5. Apague a chave privada do servidor: `shred -u /root/intrusion-monitor-actions-key*`.

## Secrets do GitHub Actions

*Settings › Secrets and variables › Actions › New repository secret*

| Secret | Valor |
|---|---|
| `SERVER_HOST` | IP ou hostname do droplet |
| `SERVER_PORT` | `22` |
| `SERVER_USER` | `monitor` |
| `SERVER_SSH_KEY` | Conteúdo da chave privada mostrada pelo `setup.sh` (inclui as linhas `-----BEGIN/END OPENSSH PRIVATE KEY-----`) |
| `SERVER_HOST_FINGERPRINT` | Fingerprint `SHA256:...` mostrado pelo `setup.sh` |

A chave do Actions está em `authorized_keys` com `restrict,command="/usr/local/bin/intrusion-monitor-deploy"`. Se ela vazar, a única coisa que permite fazer é rodar o deploy.

## Trocar a senha do painel

```bash
cd /opt/intrusion-monitor && node scripts/hash-password.js
sudo nano /etc/intrusion-monitor.env        # substitua ADMIN_PASSWORD_HASH='...'
sudo systemctl restart intrusion-monitor
```

## Desenvolvimento local

```bash
npm install
cp .env.example .env          # preencha ADMIN_PASSWORD_HASH (npm run hash-password) e SESSION_SECRET
# DEMO_MODE=true no .env usa dados de exemplo em vez dos logs da máquina
npm run dev                   # http://127.0.0.1:3100
npm test
```

## Observações

- O Cloud Firewall da DigitalOcean descarta o tráfego antes de ele chegar ao droplet. O ufw só registra o que passou por esse firewall.
- Se o ufw não gravar `/var/log/ufw.log` (sem rsyslog), o app lê os registros do kernel pelo journal.
- O nginx do container do hash-generator vê o IP do nginx do host, a menos que ele tenha `real_ip` configurado. Por isso os IPs do rate limit podem aparecer todos iguais.
- As sessões ficam em memória: cada deploy ou restart desconecta o usuário logado.

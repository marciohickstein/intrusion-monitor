// Dados de exemplo (DEMO_MODE=true) para desenvolver o painel fora do servidor.
// IPs das faixas de documentacao (RFC 5737), nunca IPs reais.
const ssh = require('./ssh');
const fail2ban = require('./fail2ban');
const ufw = require('./ufw');
const nginx = require('./nginx');

const ips = ['203.0.113.10', '203.0.113.77', '198.51.100.23', '192.0.2.150', '198.51.100.4'];
const pick = (arr, i) => arr[i % arr.length];
const now = Date.now();

function sshJournal() {
  const msgs = [];
  for (let i = 0; i < 120; i++) {
    const ip = pick(ips, i * 7);
    const user = pick(['root', 'admin', 'ubuntu', 'test', 'oracle'], i);
    const kind = i % 3;
    const MESSAGE = kind === 0 ? `Invalid user ${user} from ${ip} port ${40000 + i}`
      : kind === 1 ? `Connection closed by invalid user ${user} ${ip} port ${40000 + i} [preauth]`
      : `Disconnected from authenticating user root ${ip} port ${40000 + i} [preauth]`;
    msgs.push({ MESSAGE, __REALTIME_TIMESTAMP: String((now - (120 - i) * 600000) * 1000) });
  }
  msgs.push({ MESSAGE: 'Accepted publickey for marcio from 192.0.2.1 port 51000 ssh2: ED25519 SHA256:exemplo', __REALTIME_TIMESTAMP: String(now * 1000) });
  msgs.push({ MESSAGE: 'Accepted publickey for app from 192.0.2.200 port 52000 ssh2: ED25519 SHA256:exemplo', __REALTIME_TIMESTAMP: String((now - 3600000) * 1000) });
  return msgs.map((m) => JSON.stringify(m)).join('\n');
}

function collectAll(config) {
  const day = new Date(now).toISOString().slice(0, 10);
  const f2bLog = ips.map((ip, i) => `${day} 1${i}:00:00,000 fail2ban.actions        [99]: NOTICE  [sshd] Ban ${ip}`).join('\n')
    + `\n${day} 18:00:00,000 fail2ban.filter         [99]: INFO    [sshd] Found ${ips[0]} - ${day} 18:00:00`;
  const ufwLog = Array.from({ length: 80 }, (_, i) => `${new Date(now - i * 60000).toISOString()} droplet kernel: [UFW BLOCK] IN=eth0 OUT= SRC=${pick(ips, i)} DST=192.0.2.5 PROTO=TCP SPT=${50000 + i} DPT=${pick([23, 3389, 5432, 6379, 8080, 445], i)}`).join('\n');
  const paths = ['/', '/.env', '/wp-login.php', '/api/hash', '/.git/config', '/phpmyadmin/', '/vendor/phpunit/x.php', '/favicon.ico'];
  const accessLog = Array.from({ length: 200 }, (_, i) => {
    const p = pick(paths, i);
    const status = p === '/' || p === '/api/hash' ? 200 : 404;
    return `${pick(ips, i * 3)} - - [23/Nov/2026:10:${String(i % 60).padStart(2, '0')}:00 +0000] "GET ${p} HTTP/1.1" ${status} 153 "-" "Mozilla/5.0 (scanner)"`;
  }).join('\n');
  const dockerLog = Array.from({ length: 12 }, (_, i) => `${pick(ips, i)} - - [23/Nov/2026:11:00:0${i % 10} +0000] "POST /connect HTTP/1.1" 429 169 "-" "curl/8"`).join('\n')
    + '\n2026/11/23 11:00:01 [error] 29#29: *1 limiting requests, excess: 5.120 by zone "connect", client: 203.0.113.10';

  return {
    ssh: { ok: true, since: config.sshSince, last: ['marcio   pts/0        192.0.2.1        Mon Nov 23 10:00   still logged in'], ...ssh.summarize(ssh.parseJournal(sshJournal())) },
    fail2ban: {
      ok: true,
      jail: config.fail2banJail,
      status: { ok: true, ...fail2ban.parseStatus('Currently failed:\t3\nTotal failed:\t240\nCurrently banned:\t2\nTotal banned:\t15\nBanned IP list:\t203.0.113.10 198.51.100.23') },
      log: { ok: true, truncated: false, bans: fail2ban.parseLog(f2bLog).filter((e) => e.action !== 'Found').reverse(), topFound: [] },
    },
    ufw: { ok: true, source: 'demo', truncated: false, ...ufw.summarize(ufwLog) },
    nginx: {
      ok: true,
      access: { ok: true, source: 'demo', truncated: false, ...nginx.summarizeAccess(accessLog) },
      rateLimit: { ok: true, container: config.frontendContainer, ...nginx.summarizeRateLimit(dockerLog) },
    },
  };
}

module.exports = { collectAll };

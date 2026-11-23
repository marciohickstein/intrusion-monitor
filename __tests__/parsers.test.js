const ssh = require('../src/collectors/ssh');
const fail2ban = require('../src/collectors/fail2ban');
const ufw = require('../src/collectors/ufw');
const nginx = require('../src/collectors/nginx');

describe('ssh', () => {
  test.each([
    ['Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2', { type: 'failed', user: 'admin', ip: '203.0.113.5', method: 'password' }],
    ['Failed publickey for root from 2001:db8::1 port 22 ssh2', { type: 'failed', user: 'root', ip: '2001:db8::1' }],
    ['Invalid user oracle from 198.51.100.9 port 5000', { type: 'invalid', user: 'oracle', ip: '198.51.100.9' }],
    ['Accepted publickey for app from 192.0.2.10 port 50000 ssh2: ED25519 SHA256:x', { type: 'accepted', user: 'app', ip: '192.0.2.10' }],
    ['Connection closed by invalid user test 203.0.113.7 port 3333 [preauth]', { type: 'preauth', user: 'test', ip: '203.0.113.7' }],
    ['Disconnected from authenticating user root 203.0.113.8 port 1 [preauth]', { type: 'preauth', user: 'root', ip: '203.0.113.8' }],
    ['Connection closed by 203.0.113.9 port 2 [preauth]', { type: 'preauth', user: '', ip: '203.0.113.9' }],
  ])('%s', (msg, expected) => {
    expect(ssh.parseSshMessage(msg)).toMatchObject(expected);
  });

  test('ignora mensagens irrelevantes', () => {
    expect(ssh.parseSshMessage('Server listening on 0.0.0.0 port 22.')).toBeNull();
  });

  test('parseJournal + summarize', () => {
    const lines = [
      { MESSAGE: 'Invalid user a from 203.0.113.5 port 1', __REALTIME_TIMESTAMP: '1700000000000000' },
      { MESSAGE: 'Invalid user b from 203.0.113.5 port 2', __REALTIME_TIMESTAMP: '1700000001000000' },
      { MESSAGE: 'Accepted publickey for marcio from 192.0.2.1 port 3 ssh2', __REALTIME_TIMESTAMP: '1700000002000000' },
      'nao e json',
    ].map((l) => (typeof l === 'string' ? l : JSON.stringify(l))).join('\n');
    const s = ssh.summarize(ssh.parseJournal(lines));
    expect(s.totals).toEqual({ failed: 0, invalid: 2, preauth: 0, accepted: 1 });
    expect(s.topIps[0]).toEqual({ key: '203.0.113.5', count: 2 });
    expect(s.accepted[0]).toMatchObject({ user: 'marcio', time: '2023-11-14T22:13:22.000Z' });
  });
});

describe('fail2ban', () => {
  test('parseStatus', () => {
    const out = `Status for the jail: sshd
|- Filter
|  |- Currently failed:\t2
|  |- Total failed:\t31
|  \`- Journal matches:\t_SYSTEMD_UNIT=sshd.service + _COMM=sshd
\`- Actions
   |- Currently banned:\t2
   |- Total banned:\t5
   \`- Banned IP list:\t203.0.113.5 198.51.100.9`;
    expect(fail2ban.parseStatus(out)).toEqual({
      currentlyFailed: 2, totalFailed: 31, currentlyBanned: 2, totalBanned: 5,
      bannedIps: ['203.0.113.5', '198.51.100.9'],
    });
  });

  test('parseStatus com lista vazia', () => {
    expect(fail2ban.parseStatus('Currently banned:\t0\nBanned IP list:\t').bannedIps).toEqual([]);
  });

  test('parseLog', () => {
    const log = [
      '2026-11-23 10:00:00,123 fail2ban.actions        [812]: NOTICE  [sshd] Ban 203.0.113.5',
      '2026-11-23 11:00:00,123 fail2ban.actions        [812]: NOTICE  [sshd] Unban 203.0.113.5',
      '2026-11-23 09:59:00,001 fail2ban.filter         [812]: INFO    [sshd] Found 203.0.113.5 - 2026-11-23 09:59:00',
      '2026-11-23 09:00:00,000 fail2ban.server         [812]: INFO    Starting Fail2ban',
    ].join('\n');
    expect(fail2ban.parseLog(log)).toEqual([
      { time: '2026-11-23 10:00:00', jail: 'sshd', action: 'Ban', ip: '203.0.113.5' },
      { time: '2026-11-23 11:00:00', jail: 'sshd', action: 'Unban', ip: '203.0.113.5' },
      { time: '2026-11-23 09:59:00', jail: 'sshd', action: 'Found', ip: '203.0.113.5' },
    ]);
  });
});

describe('ufw', () => {
  test('formato syslog classico', () => {
    const line = 'Nov 23 10:00:00 droplet kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=203.0.113.5 DST=192.0.2.1 LEN=40 PROTO=TCP SPT=5555 DPT=23 WINDOW=1024';
    expect(ufw.parseLine(line)).toEqual({ time: 'Nov 23 10:00:00', action: 'BLOCK', src: '203.0.113.5', dst: '192.0.2.1', proto: 'TCP', dpt: '23', iface: 'eth0' });
  });

  test('formato ISO e summarize', () => {
    const text = [
      '2026-11-23T10:00:00.1+00:00 droplet kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.5 PROTO=TCP DPT=3389',
      '2026-11-23T10:00:01.1+00:00 droplet kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.5 PROTO=TCP DPT=3389',
      '2026-11-23T10:00:02.1+00:00 droplet kernel: [UFW AUDIT] IN=eth0 SRC=198.51.100.1 PROTO=UDP DPT=53',
      '2026-11-23T10:00:03.1+00:00 droplet kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.2 PROTO=ICMP',
    ].join('\n');
    const s = ufw.summarize(text);
    expect(s.total).toBe(3);
    expect(s.topSrc[0]).toEqual({ key: '203.0.113.5', count: 2 });
    expect(s.topPorts).toEqual([{ key: 'TCP/3389', count: 2 }, { key: 'ICMP', count: 1 }]);
    expect(s.recent[0].time).toBe('2026-11-23T10:00:03.1+00:00');
  });
});

describe('nginx', () => {
  const ok = '192.0.2.1 - - [23/Nov/2026:10:00:00 +0000] "GET /api/hash HTTP/1.1" 200 12 "-" "Mozilla"';
  const env = '203.0.113.5 - - [23/Nov/2026:10:00:01 +0000] "GET /.env HTTP/1.1" 404 10 "-" "curl"';
  const tls = '203.0.113.6 - - [23/Nov/2026:10:00:02 +0000] "\\x16\\x03\\x01" 400 157 "-" "-"';

  test('parseLine', () => {
    expect(nginx.parseLine(ok)).toMatchObject({ ip: '192.0.2.1', method: 'GET', path: '/api/hash', status: 200 });
    expect(nginx.parseLine(tls)).toMatchObject({ ip: '203.0.113.6', method: '', status: 400 });
    expect(nginx.parseLine('lixo')).toBeNull();
  });

  test('isSuspicious', () => {
    expect(nginx.isSuspicious(nginx.parseLine(ok))).toBe(false);
    expect(nginx.isSuspicious(nginx.parseLine(env))).toBe(true);
    expect(nginx.isSuspicious(nginx.parseLine(tls))).toBe(true);
  });

  test('summarizeAccess', () => {
    const s = nginx.summarizeAccess([ok, env, env, tls].join('\n'));
    expect(s.total).toBe(4);
    expect(s.statusCounts).toEqual({ '2xx': 1, '4xx': 3 });
    expect(s.suspiciousTotal).toBe(3);
    expect(s.suspiciousByIp[0]).toEqual({ key: '203.0.113.5', count: 2 });
  });

  test('summarizeRateLimit', () => {
    const text = [
      '203.0.113.5 - - [23/Nov/2026:10:00:00 +0000] "POST /connect HTTP/1.1" 429 169 "-" "curl"',
      '203.0.113.5 - - [23/Nov/2026:10:00:01 +0000] "POST /connect HTTP/1.1" 200 20 "-" "curl"',
      '2026/11/23 10:00:00 [error] 29#29: *1 limiting requests, excess: 5.1 by zone "connect", client: 203.0.113.5',
    ].join('\n');
    expect(nginx.summarizeRateLimit(text)).toMatchObject({ count429: 1, limitingCount: 1, byIp: [{ key: '203.0.113.5', count: 1 }] });
  });
});

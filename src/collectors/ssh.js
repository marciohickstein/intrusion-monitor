const { run } = require('../lib/exec');
const { top, lines } = require('../lib/stats');

const IP = '([0-9a-fA-F.:]+)';
const PATTERNS = [
  { type: 'failed', re: new RegExp(`^Failed (\\S+) for (?:invalid user )?(\\S*) from ${IP} port (\\d+)`), map: (m) => ({ method: m[1], user: m[2], ip: m[3] }) },
  { type: 'invalid', re: new RegExp(`^Invalid user (\\S*) from ${IP} port (\\d+)`), map: (m) => ({ user: m[1], ip: m[2] }) },
  { type: 'accepted', re: new RegExp(`^Accepted (\\S+) for (\\S+) from ${IP} port (\\d+)`), map: (m) => ({ method: m[1], user: m[2], ip: m[3] }) },
  // Com login so por chave, os bots aparecem assim (desconectam antes de autenticar)
  { type: 'preauth', re: new RegExp(`^(?:Connection closed by|Disconnected from) (?:(?:invalid|authenticating) user (\\S*) )?${IP} port (\\d+) \\[preauth\\]`), map: (m) => ({ user: m[1] || '', ip: m[2] }) },
];

function parseSshMessage(message) {
  for (const { type, re, map } of PATTERNS) {
    const m = re.exec(message);
    if (m) return { type, ...map(m) };
  }
  return null;
}

// Saida de "journalctl -o json": um objeto JSON por linha.
function parseJournal(text) {
  const events = [];
  for (const line of lines(text)) {
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }
    const message = Array.isArray(entry.MESSAGE) ? Buffer.from(entry.MESSAGE).toString() : String(entry.MESSAGE || '');
    const event = parseSshMessage(message);
    if (!event) continue;
    const micros = Number(entry.__REALTIME_TIMESTAMP);
    events.push({ ...event, time: micros ? new Date(micros / 1000).toISOString() : null, message });
  }
  return events;
}

function summarize(events) {
  const attacks = events.filter((e) => e.type !== 'accepted');
  const totals = { failed: 0, invalid: 0, preauth: 0, accepted: 0 };
  for (const e of events) totals[e.type] += 1;
  return {
    totals,
    topIps: top(attacks, (e) => e.ip),
    topUsers: top(attacks, (e) => e.user),
    accepted: events.filter((e) => e.type === 'accepted').slice(-30).reverse(),
    recent: attacks.slice(-50).reverse(),
  };
}

async function collect(config) {
  const journal = await run('/usr/bin/journalctl', [
    '--no-pager', '-o', 'json', '-n', '50000', '--since', config.sshSince,
    'SYSLOG_IDENTIFIER=sshd', 'SYSLOG_IDENTIFIER=sshd-session',
  ]);
  const last = await run('/usr/bin/last', ['-n', '20', '-w', '-i']);

  const result = { since: config.sshSince, last: last.ok ? lines(last.stdout) : [], lastError: last.error };
  if (!journal.ok) return { ok: false, error: journal.error, ...result };
  return { ok: true, ...result, ...summarize(parseJournal(journal.stdout)) };
}

module.exports = { collect, parseSshMessage, parseJournal, summarize };

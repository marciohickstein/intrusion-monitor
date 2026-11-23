const { sudo } = require('../lib/exec');
const { tailFile } = require('../lib/tail');
const { top, lines } = require('../lib/stats');

function parseStatus(text) {
  const num = (label) => {
    const m = new RegExp(`${label}:\\s*(\\d+)`).exec(text);
    return m ? Number(m[1]) : null;
  };
  const banned = /Banned IP list:\s*(.*)/.exec(text);
  return {
    currentlyFailed: num('Currently failed'),
    totalFailed: num('Total failed'),
    currentlyBanned: num('Currently banned'),
    totalBanned: num('Total banned'),
    bannedIps: banned ? banned[1].trim().split(/\s+/).filter(Boolean) : [],
  };
}

// 2026-11-23 10:00:00,123 fail2ban.actions [123]: NOTICE  [sshd] Ban 1.2.3.4
const LOG_RE = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+fail2ban\.\S+\s+\[\d+\]:\s+\w+\s+\[([^\]]+)\]\s+(Ban|Unban|Restore Ban|Found)\s+(\S+)/;

function parseLog(text) {
  const events = [];
  for (const line of lines(text)) {
    const m = LOG_RE.exec(line);
    if (m) events.push({ time: m[1], jail: m[2], action: m[3], ip: m[4] });
  }
  return events;
}

async function collect(config) {
  const status = await sudo('/usr/bin/fail2ban-client', ['status', config.fail2banJail]);
  const result = {
    jail: config.fail2banJail,
    status: status.ok ? { ok: true, ...parseStatus(status.stdout) } : { ok: false, error: status.error },
  };
  try {
    const { text, truncated } = await tailFile(config.fail2banLog, config.maxLogBytes);
    const events = parseLog(text);
    result.log = {
      ok: true,
      truncated,
      bans: events.filter((e) => e.action !== 'Found').slice(-50).reverse(),
      topFound: top(events.filter((e) => e.action === 'Found'), (e) => e.ip),
    };
  } catch (err) {
    result.log = { ok: false, error: `${config.fail2banLog}: ${err.message}` };
  }
  result.ok = result.status.ok || result.log.ok;
  return result;
}

module.exports = { collect, parseStatus, parseLog };

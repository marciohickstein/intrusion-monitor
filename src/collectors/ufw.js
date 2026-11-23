const { run } = require('../lib/exec');
const { tailFile } = require('../lib/tail');
const { top, lines } = require('../lib/stats');

function field(line, name) {
  const m = new RegExp(`\\b${name}=(\\S*)`).exec(line);
  return m ? m[1] : null;
}

function parseLine(line) {
  const action = /\[UFW (\w+)\]/.exec(line);
  if (!action) return null;
  // Timestamp ISO (rsyslog moderno / journalctl short-iso) ou "Nov 23 10:00:00"
  const time = /^\d{4}-\d{2}-\d{2}T/.test(line) ? line.split(' ')[0] : line.slice(0, 15);
  return {
    time,
    action: action[1],
    src: field(line, 'SRC'),
    dst: field(line, 'DST'),
    proto: field(line, 'PROTO'),
    dpt: field(line, 'DPT'),
    iface: field(line, 'IN'),
  };
}

function summarize(text) {
  const events = lines(text).map(parseLine).filter(Boolean);
  const blocked = events.filter((e) => e.action === 'BLOCK');
  return {
    total: blocked.length,
    topSrc: top(blocked, (e) => e.src),
    topPorts: top(blocked, (e) => (e.dpt ? `${e.proto}/${e.dpt}` : e.proto)),
    recent: blocked.slice(-50).reverse(),
  };
}

async function collect(config) {
  try {
    const { text, truncated } = await tailFile(config.ufwLog, config.maxLogBytes);
    return { ok: true, source: config.ufwLog, truncated, ...summarize(text) };
  } catch (fileErr) {
    // Sem rsyslog o ufw.log nao existe: o log fica so no kernel/journal.
    const journal = await run('/usr/bin/journalctl', ['--no-pager', '-k', '-o', 'short-iso', '--since', '-1d', '-n', '50000', '-g', 'UFW ']);
    if (journal.ok) return { ok: true, source: 'journalctl -k (ultimas 24h)', truncated: false, ...summarize(journal.stdout) };
    return { ok: false, error: `${config.ufwLog}: ${fileErr.message}; journalctl: ${journal.error}` };
  }
}

module.exports = { collect, parseLine, summarize };

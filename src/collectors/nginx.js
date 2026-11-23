const { sudo } = require('../lib/exec');
const { tailFile } = require('../lib/tail');
const { top, lines } = require('../lib/stats');

// Formato "combined": IP - user [data] "METODO /caminho HTTP/1.1" status bytes "referer" "user-agent"
const LINE_RE = /^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"/;

// Caminhos tipicos de scanners/bots procurando falhas
const SUSPICIOUS_RE = /(\.env|\.git\/|\.aws|\.ssh|wp-(login|admin|content|includes)|xmlrpc\.php|phpmyadmin|pma\/|\.php\b|cgi-bin|\/actuator|\/server-status|\/boaform|\/HNAP1|\/shell|\.\.\/|%2e%2e|\/etc\/passwd|\/vendor\/phpunit|\/console|\/manager\/html|\/solr|\/druid|\/telescope|\/debug)/i;

function parseLine(line) {
  const m = LINE_RE.exec(line);
  if (!m) return null;
  const [method, path] = m[3].split(' ');
  return {
    ip: m[1],
    time: m[2],
    request: m[3],
    method: path ? method : '',
    path: path || m[3],
    status: Number(m[4]),
    userAgent: m[7],
  };
}

function isSuspicious(entry) {
  // Requisicao sem metodo/caminho valido (ex.: lixo binario, handshake TLS na porta 80)
  if (!entry.method) return true;
  return SUSPICIOUS_RE.test(entry.path);
}

function summarizeAccess(text) {
  const entries = lines(text).map(parseLine).filter(Boolean);
  const errors = entries.filter((e) => e.status >= 400);
  const suspicious = entries.filter(isSuspicious);
  const statusCounts = {};
  for (const e of entries) {
    const bucket = `${Math.floor(e.status / 100)}xx`;
    statusCounts[bucket] = (statusCounts[bucket] || 0) + 1;
  }
  return {
    total: entries.length,
    statusCounts,
    errorsByIp: top(errors, (e) => e.ip),
    suspiciousByIp: top(suspicious, (e) => e.ip),
    suspiciousTotal: suspicious.length,
    suspicious: suspicious.slice(-50).reverse(),
  };
}

// Logs do nginx dentro do container (stdout = access, stderr = error log)
function summarizeRateLimit(text) {
  const all = lines(text);
  const rejected = all.map(parseLine).filter((e) => e && e.status === 429);
  const limiting = all.filter((l) => l.includes('limiting requests'));
  return {
    count429: rejected.length,
    limitingCount: limiting.length,
    byIp: top(rejected, (e) => e.ip),
    recent: limiting.slice(-20).reverse(),
  };
}

async function collect(config) {
  const result = {};
  try {
    const { text, truncated } = await tailFile(config.nginxAccessLog, config.maxLogBytes);
    result.access = { ok: true, source: config.nginxAccessLog, truncated, ...summarizeAccess(text) };
  } catch (err) {
    result.access = { ok: false, error: `${config.nginxAccessLog}: ${err.message}` };
  }

  // Argumentos fixos: precisam bater exatamente com a regra em /etc/sudoers.d/intrusion-monitor
  const docker = await sudo('/usr/bin/docker', ['logs', '--since', '24h', '--tail', '20000', config.frontendContainer]);
  result.rateLimit = docker.ok
    ? { ok: true, container: config.frontendContainer, ...summarizeRateLimit(`${docker.stdout}\n${docker.stderr}`) }
    : { ok: false, container: config.frontendContainer, error: docker.error };

  result.ok = result.access.ok || result.rateLimit.ok;
  return result;
}

module.exports = { collect, parseLine, isSuspicious, summarizeAccess, summarizeRateLimit };

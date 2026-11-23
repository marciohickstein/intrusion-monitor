const ssh = require('./ssh');
const fail2ban = require('./fail2ban');
const ufw = require('./ufw');
const nginx = require('./nginx');
const demo = require('./demo');
const { createCache } = require('../lib/cache');

function safe(fn) {
  return fn().catch((err) => ({ ok: false, error: err.message }));
}

function createCollector(config) {
  const cached = createCache(config.cacheTtlMs);
  return async function collectAll({ force = false } = {}) {
    return cached('all', async () => {
      if (config.demoMode) return { ...demo.collectAll(config), collectedAt: new Date().toISOString() };
      const [sshData, f2bData, ufwData, nginxData] = await Promise.all([
        safe(() => ssh.collect(config)),
        safe(() => fail2ban.collect(config)),
        safe(() => ufw.collect(config)),
        safe(() => nginx.collect(config)),
      ]);
      return { ssh: sshData, fail2ban: f2bData, ufw: ufwData, nginx: nginxData, collectedAt: new Date().toISOString() };
    }, { force });
  };
}

module.exports = { createCollector };

const env = process.env;

const config = {
  port: Number(env.PORT) || 3100,
  host: env.HOST || '127.0.0.1',
  isProduction: env.NODE_ENV === 'production',
  adminUser: env.ADMIN_USER || '',
  adminPasswordHash: env.ADMIN_PASSWORD_HASH || '',
  sessionSecret: env.SESSION_SECRET || '',
  sshSince: env.SSH_SINCE || '7 days ago',
  ufwLog: env.UFW_LOG || '/var/log/ufw.log',
  fail2banLog: env.FAIL2BAN_LOG || '/var/log/fail2ban.log',
  fail2banJail: env.FAIL2BAN_JAIL || 'sshd',
  nginxAccessLog: env.NGINX_ACCESS_LOG || '/var/log/nginx/access.log',
  frontendContainer: env.FRONTEND_CONTAINER || 'hash-generator-frontend-1',
  maxLogBytes: Number(env.MAX_LOG_BYTES) || 10 * 1024 * 1024,
  cacheTtlMs: 30 * 1000,
  demoMode: env.DEMO_MODE === 'true',
};

function validateConfig(cfg = config) {
  const problems = [];
  if (!cfg.adminUser) problems.push('ADMIN_USER nao definido');
  if (!/^\$2[aby]\$\d{2}\$.{53}$/.test(cfg.adminPasswordHash)) {
    problems.push('ADMIN_PASSWORD_HASH ausente ou invalido (gere com: npm run hash-password)');
  }
  if (cfg.sessionSecret.length < 32) {
    problems.push('SESSION_SECRET ausente ou com menos de 32 caracteres');
  }
  return problems;
}

module.exports = { config, validateConfig };

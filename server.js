// Em desenvolvimento carrega o .env; em producao o systemd injeta as variaveis.
try { process.loadEnvFile(); } catch { /* sem .env */ }

const { config, validateConfig } = require('./src/config');
const { createApp } = require('./src/app');

const problems = validateConfig(config);
if (problems.length) {
  console.error(`Configuracao invalida:\n - ${problems.join('\n - ')}`);
  process.exit(1);
}

createApp(config).listen(config.port, config.host, () => {
  console.log(`intrusion-monitor ouvindo em http://${config.host}:${config.port}${config.demoMode ? ' (DEMO)' : ''}`);
});

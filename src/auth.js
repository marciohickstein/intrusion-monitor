const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');

// Hash usado quando o usuario nao confere, para o tempo de resposta ser o mesmo.
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 12);

function sameString(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

async function verifyCredentials(config, username, password) {
  const userOk = sameString(username || '', config.adminUser);
  const hash = userOk ? config.adminPasswordHash : DUMMY_HASH;
  const passOk = await bcrypt.compare(String(password || ''), hash);
  return userOk && passOk;
}

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/login');
}

// Bloqueia POST vindo de outro site (complementa o cookie SameSite=Strict).
function sameOrigin(req, res, next) {
  if (req.method !== 'POST') return next();
  const origin = req.get('origin');
  if (!origin) return next();
  try {
    if (new URL(origin).host === req.get('host')) return next();
  } catch { /* origem invalida */ }
  return res.status(403).send('Origem nao permitida');
}

module.exports = { verifyCredentials, requireAuth, sameOrigin };

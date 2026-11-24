const path = require('node:path');
const express = require('express');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { verifyCredentials, requireAuth, sameOrigin } = require('./auth');
const { createCollector } = require('./collectors');
const pkg = require('../package.json');

function createApp(config, { collectAll = createCollector(config) } = {}) {
  const app = express();

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '..', 'views'));
  app.set('trust proxy', 1); // atras do nginx do host
  app.disable('x-powered-by');

  app.use(helmet({
    // "no-referrer" (padrao do helmet) faz o navegador mandar Origin: null ate em
    // POSTs do proprio site; "same-origin" mantem a origem real em requisicoes internas.
    referrerPolicy: { policy: 'same-origin' },
  }));
  app.use(express.static(path.join(__dirname, '..', 'public'), { maxAge: '1h' }));
  app.use(express.urlencoded({ extended: false, limit: '10kb' }));
  app.use(session({
    name: 'im.sid',
    secret: config.sessionSecret,
    store: new MemoryStore({ checkPeriod: 60 * 60 * 1000 }),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'strict',
      secure: config.isProduction,
      maxAge: 8 * 60 * 60 * 1000,
    },
  }));
  app.use(sameOrigin);
  app.use((req, res, next) => {
    res.locals.version = pkg.version;
    res.locals.user = req.session.user;
    next();
  });

  app.get('/healthz', (req, res) => res.type('text').send('ok'));

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    handler: (req, res) => res.status(429).render('login', { error: 'Muitas tentativas. Tente novamente em 15 minutos.' }),
  });

  app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/');
    return res.render('login', { error: null });
  });

  app.post('/login', loginLimiter, async (req, res, next) => {
    try {
      const { username, password } = req.body || {};
      if (!(await verifyCredentials(config, username, password))) {
        return res.status(401).render('login', { error: 'Usuario ou senha invalidos.' });
      }
      return req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.user = config.adminUser;
        return res.redirect('/');
      });
    } catch (err) {
      return next(err);
    }
  });

  app.post('/logout', (req, res) => {
    req.session.destroy(() => {
      res.clearCookie('im.sid');
      res.redirect('/login');
    });
  });

  app.get('/', requireAuth, async (req, res, next) => {
    try {
      const data = await collectAll({ force: req.query.refresh === '1' });
      res.set('Cache-Control', 'no-store');
      return res.render('dashboard', { data });
    } catch (err) {
      return next(err);
    }
  });

  app.use((req, res) => res.status(404).type('text').send('Nao encontrado'));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).type('text').send('Erro interno');
  });

  return app;
}

module.exports = { createApp };

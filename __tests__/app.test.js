const request = require('supertest');
const bcrypt = require('bcryptjs');
const { createApp } = require('../src/app');
const { validateConfig } = require('../src/config');

const config = {
  adminUser: 'admin',
  adminPasswordHash: bcrypt.hashSync('senha-de-teste-123', 4),
  sessionSecret: 'x'.repeat(40),
  isProduction: false,
  sshSince: '7 days ago',
  fail2banJail: 'sshd',
  frontendContainer: 'hash-generator-frontend-1',
  cacheTtlMs: 0,
  demoMode: true,
};

function makeApp() {
  return createApp(config);
}

function login(agent, password = 'senha-de-teste-123') {
  return agent.post('/login').type('form').send({ username: 'admin', password });
}

test('validateConfig acusa configuracao ausente', () => {
  expect(validateConfig({ adminUser: '', adminPasswordHash: '', sessionSecret: '' })).toHaveLength(3);
  expect(validateConfig(config)).toEqual([]);
});

test('healthz e publico', async () => {
  await request(makeApp()).get('/healthz').expect(200, 'ok');
});

test('painel exige login', async () => {
  await request(makeApp()).get('/').expect(302).expect('Location', '/login');
});

test('senha errada retorna 401', async () => {
  const res = await login(request.agent(makeApp()), 'errada');
  expect(res.status).toBe(401);
  expect(res.text).toContain('invalidos');
});

test('login correto abre o painel e logout encerra a sessao', async () => {
  const agent = request.agent(makeApp());
  await login(agent).expect(302).expect('Location', '/');
  const page = await agent.get('/').expect(200);
  expect(page.text).toContain('1 · SSH');
  expect(page.text).toContain('203.0.113.10');
  await agent.post('/logout').expect(302);
  await agent.get('/').expect(302);
});

test('bloqueia apos 5 tentativas erradas', async () => {
  const agent = request.agent(makeApp());
  for (let i = 0; i < 5; i++) await login(agent, 'errada');
  await login(agent, 'errada').expect(429);
});

test('rejeita POST de outra origem', async () => {
  await request(makeApp()).post('/login').set('Origin', 'https://evil.example').type('form')
    .send({ username: 'admin', password: 'senha-de-teste-123' }).expect(403);
});

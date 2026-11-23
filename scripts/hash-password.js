// Gera o ADMIN_PASSWORD_HASH. Uso: npm run hash-password  (pede a senha sem mostrar)
const bcrypt = require('bcryptjs');
const readline = require('node:readline');

function ask(prompt) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(prompt)) rl.output.write(s); };
    rl.question(prompt, (answer) => { rl.close(); process.stdout.write('\n'); resolve(answer); });
  });
}

(async () => {
  const password = process.env.PASSWORD || await ask('Senha: ');
  if (password.length < 12) {
    console.error('Use pelo menos 12 caracteres.');
    process.exit(1);
  }
  if (!process.env.PASSWORD && password !== await ask('Repita a senha: ')) {
    console.error('As senhas nao conferem.');
    process.exit(1);
  }
  console.log(bcrypt.hashSync(password, 12));
})();

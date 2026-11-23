const { execFile } = require('node:child_process');

// Executa um binario sem shell (argumentos fixos, nada vindo do usuario).
function run(cmd, args, { timeout = 20000 } = {}) {
  return new Promise((resolve) => {
    execFile(
      cmd,
      args,
      { timeout, maxBuffer: 64 * 1024 * 1024, env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C' } },
      (error, stdout, stderr) => {
        resolve({
          ok: !error,
          stdout: stdout || '',
          stderr: stderr || '',
          error: error ? (stderr || error.message).trim() : null,
        });
      },
    );
  });
}

// Comandos que exigem root rodam via sudo -n (sem senha; liberados em /etc/sudoers.d).
function sudo(cmd, args, opts) {
  return run('/usr/bin/sudo', ['-n', cmd, ...args], opts);
}

module.exports = { run, sudo };

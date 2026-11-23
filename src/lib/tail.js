const fs = require('node:fs/promises');

// Le no maximo os ultimos maxBytes do arquivo, descartando a primeira linha parcial.
async function tailFile(path, maxBytes) {
  const handle = await fs.open(path, 'r');
  try {
    const { size } = await handle.stat();
    const start = Math.max(0, size - maxBytes);
    const length = size - start;
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, start);
    let text = buffer.toString('utf8');
    if (start > 0) text = text.slice(text.indexOf('\n') + 1);
    return { text, truncated: start > 0, size };
  } finally {
    await handle.close();
  }
}

module.exports = { tailFile };

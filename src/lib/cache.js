// Cache em memoria por chave, para nao reler logs a cada refresh.
function createCache(ttlMs) {
  const store = new Map();
  return async function cached(key, fn, { force = false } = {}) {
    const hit = store.get(key);
    if (!force && hit && Date.now() - hit.at < ttlMs) return hit.value;
    const value = await fn();
    store.set(key, { at: Date.now(), value });
    return value;
  };
}

module.exports = { createCache };

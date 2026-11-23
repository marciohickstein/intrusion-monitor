function countBy(items, keyFn) {
  const counts = new Map();
  for (const item of items) {
    const key = keyFn(item);
    if (key === undefined || key === null || key === '') continue;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return counts;
}

function top(items, keyFn, limit = 10) {
  return [...countBy(items, keyFn)]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([key, count]) => ({ key, count }));
}

function lines(text) {
  return text.split('\n').filter(Boolean);
}

module.exports = { countBy, top, lines };

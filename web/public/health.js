// Fills the source-health table. Text only (textContent), never innerHTML.
function ago(iso) {
  if (!iso) return 'never';
  const m = Math.round((Date.now() - Date.parse(iso)) / 60000);
  return m < 1 ? 'just now' : m < 90 ? `${m} min ago` : `${Math.round(m / 60)} h ago`;
}

const body = document.getElementById('health');
fetch('/api/incidents')
  .then((r) => (r.ok ? r.json() : Promise.reject(new Error(String(r.status)))))
  .then((data) => {
    const rows = Object.entries(data.health || {})
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([name, h]) => {
        const tr = document.createElement('tr');
        for (const text of [name, h.ok ? '● ok' : '● failing', h.ok ? String(h.items ?? 0) : '–', ago(h.last_ok)]) {
          const td = document.createElement('td');
          td.textContent = text;
          tr.append(td);
        }
        tr.children[1].className = h.ok ? 'num' : 'muted';
        return tr;
      });
    body.replaceChildren(...rows);
  })
  .catch(() => {
    body.firstElementChild.firstElementChild.textContent = 'Could not load source health.';
  });

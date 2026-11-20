// Dashboard renderer. All data comes from third-party feeds, so it is treated as
// untrusted: text goes in via textContent (never innerHTML), and links must be http(s).

const $ = (sel) => document.querySelector(sel);

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') n.className = v;
    else n.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    n.append(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
  }
  return n;
}

function safeHref(u) {
  try {
    const url = new URL(u);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

function ago(iso) {
  if (!iso) return 'never';
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 90) return 'just now';
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

function primaryLink(inc) {
  const order = ['news', 'gov', 'vendor', 'kev', 'ghsa', 'nvd'];
  for (const kind of order) {
    const it = inc.items.find((i) => i.kind === kind && safeHref(i.url));
    if (it) return safeHref(it.url);
  }
  return null;
}

function card(inc) {
  const link = primaryLink(inc);
  const kev = inc.items.some((i) => i.kev);
  const epss = Math.max(...inc.items.map((i) => i.epss ?? -1));
  const cvss = Math.max(...inc.items.map((i) => i.cvss ?? -1));

  const badges = el('ul', { class: 'badges' });
  if (kev) badges.append(el('li', {}, el('span', { class: 'badge kev' }, 'KEV · exploited')));
  if (cvss >= 0) badges.append(el('li', {}, el('span', { class: 'badge' }, `CVSS ${cvss.toFixed(1)}`)));
  if (epss >= 0) badges.append(el('li', {}, el('span', { class: 'badge' }, `EPSS ${(epss * 100).toFixed(0)}%`)));
  for (const w of inc.watch) badges.append(el('li', {}, el('span', { class: 'badge watch' }, w)));
  for (const c of inc.cves.slice(0, 6)) {
    badges.append(el('li', {}, el('a', { class: 'badge', href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`, rel: 'noopener noreferrer', target: '_blank' }, c)));
  }
  if (inc.cves.length > 6) badges.append(el('li', {}, el('span', { class: 'badge' }, `+${inc.cves.length - 6} more`)));

  const rows = inc.breakdown.map(([reason, pts]) =>
    el('tr', {}, el('td', {}, reason), el('td', { class: `pts${pts < 0 ? ' neg' : ''}` }, pts < 0 ? `${pts}` : `+${pts}`)),
  );
  const sources = inc.items.map((i) => {
    const href = safeHref(i.url);
    return el('li', {}, el('span', { class: 'mono' }, `${i.source}: `), href ? el('a', { href, rel: 'noopener noreferrer', target: '_blank' }, i.title) : i.title);
  });

  return el(
    'li',
    { class: `card inc ${inc.level}`, id: `i-${inc.id}`, 'data-level': inc.level },
    el(
      'div',
      { class: 'inc-head' },
      el(
        'div',
        {},
        el('span', { class: `level ${inc.level}` }, inc.level),
        el('h2', {}, link ? el('a', { href: link, rel: 'noopener noreferrer', target: '_blank' }, inc.title) : inc.title),
      ),
      el(
        'div',
        { class: 'score', title: 'Score out of 100' },
        el('div', { class: 'num' }, inc.score),
        el('div', { class: 'of' }, '/100'),
        el('div', { class: 'meter' }, el('span', { style: null, 'data-w': inc.score })),
      ),
    ),
    el('p', { class: 'meta' },
      el('span', {}, `First seen ${ago(inc.first_seen)}`),
      el('span', {}, `Updated ${ago(inc.last_seen)}`),
      el('span', {}, `${inc.sources.length} source${inc.sources.length === 1 ? '' : 's'}`),
    ),
    badges,
    el('details', { class: 'why' },
      el('summary', {}, 'Why this score?'),
      el('table', {}, el('tbody', {}, rows)),
      el('ul', {}, sources),
    ),
  );
}

let data = null;
let filter = 'all';

function render() {
  const list = $('#incidents');
  const shown = data.incidents.filter((i) => filter === 'all' || i.level === filter);
  list.replaceChildren(
    ...(shown.length
      ? shown.map(card)
      : [el('li', { class: 'card empty' }, el('p', {}, 'All quiet. Nothing at this level right now.'), el('p', { class: 'muted' }, 'That is a good thing.'))]),
  );
  // Meter widths: set via CSSOM (allowed by CSP), not inline style attributes.
  for (const s of list.querySelectorAll('.meter span')) s.style.width = `${s.dataset.w}%`;
  if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView();
}

function renderStatus() {
  const h = Object.values(data.health || {});
  const ok = h.filter((s) => s.ok).length;
  const allOk = ok === h.length;
  $('#status').replaceChildren(
    el('span', {}, el('span', { class: `dot${allOk ? '' : ' warn'}` }), `Last scan ${ago(data.generated)}`),
    el('span', {}, `${ok}/${h.length} sources healthy`),
    el('span', {}, `${data.incidents.length} active incident${data.incidents.length === 1 ? '' : 's'}`),
  );
  for (const lvl of ['all', 'critical', 'high', 'elevated']) {
    const n = lvl === 'all' ? data.incidents.length : data.incidents.filter((i) => i.level === lvl).length;
    $(`#n-${lvl}`).textContent = String(n);
  }
}

async function load() {
  try {
    const r = await fetch('/api/incidents', { headers: { Accept: 'application/json' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    data = await r.json();
    $('#filters').hidden = false;
    renderStatus();
    render();
  } catch (e) {
    $('#status').replaceChildren(el('span', {}, el('span', { class: 'dot warn' }), 'Could not load the latest scan. Retrying shortly.'));
  }
}

$('#filters').addEventListener('click', (e) => {
  const b = e.target.closest('button[data-level]');
  if (!b) return;
  filter = b.dataset.level;
  for (const c of document.querySelectorAll('#filters .chip')) c.setAttribute('aria-pressed', String(c === b));
  render();
});

load();
setInterval(load, 5 * 60 * 1000);

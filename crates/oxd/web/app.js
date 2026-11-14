// The Netoxide web interface. One file, no build step, no dependencies.
//
// Everything on screen comes from the daemon's API. The page holds no data
// of its own, and every call carries the access token the user signed in
// with. Text from the daemon is always inserted as text, never as HTML.
'use strict';

const app = document.getElementById('app');

/** Builds an element. `attrs` may hold `class`, `on<event>` handlers and attributes. */
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const state = {
  token: sessionStorage.getItem('ox-token') || '',
  me: null,
  view: 'overview',
  status: null,
  running: null,      // { config, summary, describe }
  hits: {},           // rule ID -> packets
  leases: [],
  candidate: null,    // selected candidate name
  meta: null,
  plan: null,
  form: null,         // 'forward' | 'block' | 'edit'
  draft: { name: '', text: '' },
  explain: { src: '', dst: '', proto: 'tcp', dport: '', in: '', compare: true, result: null },
  audit: [],
  tokens: [],
  newToken: null,
  notice: null,       // { kind: 'ok' | 'bad', text }
  problem: null,      // why the daemon cannot be read
};

/** Calls the API. Resolves to parsed JSON, or text for non-JSON answers. */
async function call(method, path, body, type) {
  const headers = { Authorization: 'Bearer ' + state.token };
  if (body != null) headers['Content-Type'] = type || 'application/json';
  const res = await fetch(path, {
    method,
    headers,
    body: body == null ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)),
  });
  const text = await res.text();
  let data = text;
  if ((res.headers.get('content-type') || '').includes('json')) {
    try { data = JSON.parse(text); } catch (e) { /* leave as text */ }
  }
  if (!res.ok) {
    const err = new Error((data && data.error) || ('the daemon answered ' + res.status));
    err.status = res.status;
    throw err;
  }
  return data;
}

function may(action) {
  const role = state.me && state.me.role;
  if (action === 'read') return true;
  if (action === 'audit') return role !== 'viewer';
  if (action === 'manage' || action === 'rollback') return role === 'admin';
  return role === 'operator' || role === 'admin';
}

function when(secs) {
  if (!secs) return '';
  return new Date(secs * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

function mmss(secs) {
  return String(Math.floor(secs / 60)).padStart(2, '0') + ':' + String(secs % 60).padStart(2, '0');
}

/** Runs an action, shows what happened, then reads everything again. */
async function act(fn, done) {
  try {
    const result = await fn();
    state.notice = { kind: 'ok', text: typeof done === 'function' ? done(result) : done };
  } catch (e) {
    state.notice = { kind: 'bad', text: 'Refused: ' + e.message };
  }
  await refresh(true);
}

function parseHits(dump) {
  const hits = {};
  for (const item of (dump && dump.nftables) || []) {
    const rule = item.rule;
    if (!rule || !rule.comment) continue;
    let packets = null;
    for (const e of rule.expr || []) {
      if (e.counter && typeof e.counter.packets === 'number') packets = (packets || 0) + e.counter.packets;
    }
    if (packets != null) hits[rule.comment] = (hits[rule.comment] || 0) + packets;
  }
  return hits;
}

async function refresh(rerender) {
  if (!state.token) return render();
  try {
    state.me = await call('GET', '/v1/whoami');
    state.status = await call('GET', '/v1/status');
    try {
      state.running = await call('GET', '/v1/running/json');
    } catch (e) {
      if (e.status !== 404) throw e;
      state.running = null;
    }
    state.hits = parseHits(await call('GET', '/v1/kernel').catch(() => null));
    state.leases = await call('GET', '/v1/leases');
    const names = state.status.candidates || [];
    if (!names.includes(state.candidate)) state.candidate = names[0] || null;
    if (state.candidate) {
      state.meta = await call('GET', '/v1/candidates/' + state.candidate + '/meta').catch(() => null);
      state.plan = await call('POST', '/v1/candidates/' + state.candidate + '/plan', '').catch((e) => ({ error: e.message }));
    } else {
      state.meta = state.plan = null;
    }
    if (state.view === 'audit' && may('audit')) state.audit = (await call('GET', '/v1/audit')).entries;
    if (state.view === 'settings' && may('manage')) state.tokens = await call('GET', '/v1/tokens');
    state.problem = null;
  } catch (e) {
    if (e.status === 401) {
      state.token = '';
      sessionStorage.removeItem('ox-token');
      state.problem = e.message;
    } else {
      state.problem = e.message;
    }
  }
  // Views with a form are not redrawn on the timer, so typing is not lost.
  const hasForm = ['changes', 'explain', 'settings'].includes(state.view);
  if (rerender || !hasForm) render(); else renderChrome();
}

// ── drawing ─────────────────────────────────────────────────────────────

const VIEWS = [
  ['overview', 'Overview'], ['rules', 'Rules'], ['nat', 'NAT'], ['network', 'Network'],
  ['changes', 'Changes'], ['explain', 'Explain'], ['audit', 'Audit'], ['settings', 'Settings'],
];

function chrome() {
  const s = state.status || {};
  const run = s.running;
  const top = h('header', { class: 'top' },
    h('span', { class: 'brand' }, 'Netoxide'),
    h('span', { class: 'fact' }, h('b', null, state.running ? state.running.config.hostname : 'no config')),
    h('span', { class: 'fact' }, run ? ['running ', h('b', null, '#' + run.id)] : 'no commit yet'),
    h('span', { class: 'fact' }, (s.candidates || []).length + ' candidate' + ((s.candidates || []).length === 1 ? '' : 's')),
    s.applier && s.applier !== 'kernel' ? h('span', { class: 'tag note' }, 'dry run: nothing is loaded') : null,
    h('span', { class: 'spacer' }),
    state.me ? h('span', { class: 'fact' }, state.me.name + ' (' + state.me.role + ')') : null,
    h('button', { onclick: signOut }, 'Sign out'));

  const nav = h('nav', null, VIEWS
    .filter(([id]) => id !== 'audit' || may('audit'))
    .map(([id, label]) => h('button', {
      class: state.view === id ? 'on' : '',
      onclick: () => { state.view = id; state.notice = null; refresh(true); },
    }, label)));

  const banners = [];
  if (state.problem) banners.push(h('div', { class: 'banner bad' }, 'Cannot read the daemon: ' + state.problem));
  if (s.reverts_in != null && run) {
    banners.push(h('div', { class: 'banner warn' },
      h('span', { class: 'grow' }, 'Commit #' + run.id + ' is applied and undoes itself in ' + mmss(s.reverts_in) + ' unless you keep it.'),
      may('commit') ? h('button', { class: 'primary', onclick: () => act(() => call('POST', '/v1/confirm'), (c) => 'Kept commit #' + c.id + '.') }, 'Keep it') : null,
      may('commit') ? h('button', { class: 'danger', onclick: () => act(() => call('POST', '/v1/revert'), (c) => 'Undid commit #' + c.id + '. The candidate is kept.') }, 'Undo now') : null));
  }
  if (s.lockdown) banners.push(h('div', { class: 'banner warn' }, 'This box has no config yet. Inbound and forwarded traffic is dropped until the first commit.'));
  if (state.notice) banners.push(h('div', { class: 'banner ' + state.notice.kind }, state.notice.text));
  return [top, nav, ...banners];
}

function renderChrome() {
  const old = document.getElementById('chrome');
  if (old) old.replaceChildren(...chrome());
}

function render() {
  if (!state.token) {
    app.replaceChildren(signIn());
    return;
  }
  const views = { overview, rules, nat, network, changes, explainView, audit, settings };
  const draw = views[state.view === 'explain' ? 'explainView' : state.view] || overview;
  app.replaceChildren(h('div', { id: 'chrome' }, chrome()), h('main', null, draw()));
}

function signIn() {
  const input = h('input', { type: 'password', placeholder: 'ox_…', autocomplete: 'off', 'aria-label': 'Access token' });
  const go = (e) => {
    e.preventDefault();
    state.token = input.value.trim();
    sessionStorage.setItem('ox-token', state.token);
    state.problem = null;
    refresh(true);
  };
  return h('form', { class: 'panel signin', onsubmit: go },
    h('h1', null, 'Netoxide'),
    h('p', { class: 'dim' }, 'Sign in with an access token. An administrator makes one on the box with ',
      h('code', null, 'ox token create <name> --role operator'), '.'),
    state.problem ? h('p', { class: 'change-del' }, state.problem) : null,
    h('label', { for: 'token' }, 'Access token'),
    Object.assign(input, { id: 'token' }),
    h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Sign in')));
}

function signOut() {
  state.token = '';
  state.me = null;
  sessionStorage.removeItem('ox-token');
  render();
}

function table(head, rows) {
  return h('table', null,
    h('thead', null, h('tr', null, head.map((c) => h('th', { class: c.num ? 'num' : '' }, c.label || c)))),
    h('tbody', null, rows.map((r) => h('tr', null, r.map((cell, i) => h('td', { class: head[i] && head[i].num ? 'num' : '' }, cell))))));
}

function noConfig() {
  return h('div', { class: 'panel' },
    h('h2', null, 'No config yet'),
    h('p', null, 'Nothing has been committed, so there is nothing to show here.'),
    h('p', { class: 'dim' }, 'On the box, run ', h('code', null, 'ox init --save starter'), ' then ', h('code', null, 'ox commit starter --confirm 5m'), '. Or open Changes and write a config.'));
}

function overview() {
  const s = state.status || {};
  if (!state.running) return noConfig();
  const run = s.running;
  return [
    h('div', { class: 'grid' },
      h('div', { class: 'panel' },
        h('h2', null, 'Running'),
        h('p', null, h('b', null, 'Commit #' + run.id), run.state === 'pending' ? ' (not yet kept)' : ''),
        h('p', { class: 'dim' }, 'by ' + run.author + ' · ' + when(run.time)),
        h('p', { class: 'dim' }, run.source + (run.reason ? ' · ' + run.reason : '')),
        h('p', { class: 'dim' }, state.running.summary)),
      h('div', { class: 'panel' },
        h('h2', null, 'Services'),
        (s.services || []).length
          ? h('ul', { class: 'plain' }, s.services.map(([n, st]) => h('li', null, n + ': ' + st)))
          : h('p', { class: 'dim' }, 'The box serves no DNS or DHCP.'),
        h('p', { class: 'dim' }, state.leases.length + ' address' + (state.leases.length === 1 ? '' : 'es') + ' handed out'),
        s.four_eyes ? h('p', null, h('span', { class: 'tag note' }, 'four-eyes on'), ' a commit needs a second person') : null)),
    h('div', { class: 'panel' },
      h('h2', null, 'What this box does'),
      h('ul', { class: 'plain' }, state.running.describe.map((line) => h('li', null, line)))),
  ];
}

function hits(id) {
  const n = state.hits[id];
  return n == null ? '—' : n.toLocaleString();
}

function rules() {
  if (!state.running) return noConfig();
  const policies = state.running.config.policy || [];
  if (!policies.length) return h('div', { class: 'panel' }, 'The running config has no policies, so every forwarded packet is dropped.');
  const list = (v) => (v || ['any']).join(', ');
  return policies.map((p) => h('div', { class: 'panel' },
    h('h2', null, p.from + ' → ' + p.to),
    table(['#', 'ID', 'Rule', 'Source', 'Destination', 'Service', 'Action', { label: 'Packets', num: true }],
      (p.rule || []).map((r, i) => [
        i + 1,
        h('span', { class: 'id' }, r.id),
        [r.name, r.enabled === false ? h('span', { class: 'tag note' }, 'disabled') : null, r.reason ? h('div', { class: 'dim' }, r.reason) : null],
        list(r.source), list(r.destination), list(r.service),
        h('span', { class: 'tag ' + r.action }, r.action + (r.log ? ', logged' : '')),
        hits(r.id),
      ]).concat([['—', '', h('span', { class: 'dim' }, 'everything else'), 'any', 'any', 'any',
        h('span', { class: 'tag drop' }, 'drop' + (p.log_default === false ? '' : ', logged')),
        hits('default ' + p.from + '-' + p.to)]]))));
}

function nat() {
  if (!state.running) return noConfig();
  const n = state.running.config.nat || {};
  return [
    h('div', { class: 'panel' },
      h('h2', null, 'Port forwards'),
      (n.forward || []).length
        ? table(['ID', 'Name', 'From', 'Outside', 'Inside', 'Filter rule', { label: 'Packets', num: true }],
          n.forward.map((f) => [h('span', { class: 'id' }, f.id), f.name, f.from, f.address + ' ' + f.service,
            f.to + (f.to_port ? ' port ' + f.to_port : ''), h('span', { class: 'id' }, f.rule), hits(f.id)]))
        : h('p', { class: 'dim' }, 'None. Add one under Changes.'),
      h('p', { class: 'dim' }, 'A forward only rewrites the destination. Its filter rule decides whether the traffic gets in.')),
    h('div', { class: 'panel' },
      h('h2', null, 'Outbound'),
      (n.outbound || []).length
        ? table(['ID', 'Name', 'Zones', 'Source', 'Appears as', { label: 'Packets', num: true }],
          n.outbound.map((o) => [h('span', { class: 'id' }, o.id), o.name, o.from + ' → ' + o.to,
            (o.source || ['any']).join(', '), o.translate === 'masquerade' ? "the box's own address" : o.translate, hits(o.id)]))
        : h('p', { class: 'dim' }, 'None.')),
  ];
}

function network() {
  if (!state.running) return noConfig();
  const c = state.running.config;
  const zones = c.zones || {};
  const out = [h('div', { class: 'panel' },
    h('h2', null, 'Interfaces'),
    table(['Interface', 'Zone', '', 'Addresses', ''],
      Object.entries(c.interfaces || {}).map(([name, i]) => [h('b', null, name), i.zone,
        h('span', { class: 'dim' }, (zones[i.zone] || {}).description || ''),
        (i.addresses || []).join(', ') || h('span', { class: 'dim' }, 'no fixed address'),
        i.default_route ? 'default route' : ''])),
    h('p', { class: 'dim' }, 'From the running config. Link state is not read yet.'))];
  if (c.dns) {
    out.push(h('div', { class: 'panel' },
      h('h2', null, 'DNS'),
      h('p', null, 'Answers for ' + c.dns.zones.join(', ') + ', forwarding to ' + c.dns.upstream.join(', ') +
        (c.dns.dnssec === false ? '.' : ', with DNSSEC checking.') + (c.dns.domain ? ' Local names end in .' + c.dns.domain + '.' : '')),
      (c.dns.host || []).length ? table(['Name', 'Address'], c.dns.host.map((x) => [x.name, x.address])) : null));
  }
  const pools = Object.entries(c.dhcp || {});
  if (pools.length || state.leases.length) {
    out.push(h('div', { class: 'panel' },
      h('h2', null, 'Addresses handed out'),
      pools.map(([name, p]) => h('p', null, name + ': ' + p.first + ' to ' + p.last + ', kept for ' + (p.lease || '12h') +
        ((p.static || []).length ? ', ' + p.static.length + ' fixed' : ''))),
      state.leases.length
        ? table(['Address', 'Hardware address', 'Name', 'Until'],
          state.leases.map((l) => [l.address, h('span', { class: 'id' }, l.mac), l.name || h('span', { class: 'dim' }, 'no name'), when(l.expires)]))
        : h('p', { class: 'dim' }, 'No device has asked for an address yet.')));
  }
  return out;
}

function field(label, key, obj, attrs) {
  const id = 'f-' + key;
  const input = h('input', Object.assign({ id, value: obj[key] || '', oninput: (e) => { obj[key] = e.target.value; } }, attrs || {}));
  return h('div', null, h('label', { for: id }, label), input);
}

function changes() {
  const names = (state.status && state.status.candidates) || [];
  const pending = state.status && state.status.reverts_in != null;
  const open = (form) => () => { state.form = form; state.notice = null; render(); };
  const left = h('div', { class: 'panel list' },
    h('h2', null, 'Candidates'),
    names.length ? names.map((n) => h('button', {
      class: n === state.candidate && !state.form ? 'on' : '',
      onclick: () => { state.candidate = n; state.form = null; refresh(true); },
    }, n)) : h('p', { class: 'dim' }, 'None. A candidate is a proposed config that is not applied yet.'),
    may('edit') ? [
      h('h2', null, 'New change'),
      h('button', { onclick: open('forward'), disabled: !state.running }, 'Forward a port'),
      h('button', { onclick: open('block'), disabled: !state.running }, 'Block a device'),
      h('button', { onclick: () => { state.draft = { name: '', text: '' }; state.form = 'edit'; loadDraft(); } }, 'Edit the config'),
    ] : null);

  let right;
  if (state.form === 'forward') right = forwardForm();
  else if (state.form === 'block') right = blockForm();
  else if (state.form === 'edit') right = editForm();
  else if (state.candidate) right = candidatePanel(pending);
  else right = h('div', { class: 'panel' }, h('p', { class: 'dim' }, 'Choose a candidate, or start a new change.'));
  return h('div', { class: 'split' }, left, h('div', null, right));
}

const draftForward = { name: '', port: 'tcp/443', to: '', to_port: '', address: '' };
const draftBlock = { address: '', name: '' };

function saved(result) {
  state.candidate = result.candidate;
  state.form = null;
  return result.done.join(' ') + ' Saved as candidate ' + result.candidate + '. Nothing is applied yet.';
}

function forwardForm() {
  const go = (e) => {
    e.preventDefault();
    const body = { name: draftForward.name, port: draftForward.port, to: draftForward.to };
    if (draftForward.to_port) body.to_port = Number(draftForward.to_port);
    if (draftForward.address) body.address = draftForward.address;
    act(() => call('POST', '/v1/actions/forward', body), saved);
  };
  return h('form', { class: 'panel', onsubmit: go },
    h('h2', null, 'Forward a port'),
    h('p', { class: 'dim' }, 'Lets people on the internet reach one port of one device inside. The rule it needs is added for you and checked.'),
    h('div', { class: 'fields' },
      field('What is it for?', 'name', draftForward, { required: true, placeholder: 'Home Assistant' }),
      field('Outside port', 'port', draftForward, { required: true, placeholder: 'tcp/443' }),
      field('Inside device address', 'to', draftForward, { required: true, placeholder: '192.168.10.20' }),
      field('Inside port, if different', 'to_port', draftForward, { inputmode: 'numeric', placeholder: 'same' }),
      field('Outside address, if the box has several', 'address', draftForward, { placeholder: "the box's own" })),
    h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Save as candidate'),
      h('button', { type: 'button', onclick: () => { state.form = null; render(); } }, 'Cancel')));
}

function blockForm() {
  const go = (e) => {
    e.preventDefault();
    act(() => call('POST', '/v1/actions/block', { address: draftBlock.address, name: draftBlock.name }), saved);
  };
  return h('form', { class: 'panel', onsubmit: go },
    h('h2', null, 'Block a device'),
    h('p', { class: 'dim' }, 'Drops and logs everything the device sends, to other networks and to the box. Connections it already has open end on their own.'),
    h('div', { class: 'fields' },
      field('Device address', 'address', draftBlock, { required: true, placeholder: '192.168.10.66' }),
      field('What is it?', 'name', draftBlock, { placeholder: 'Smart TV' })),
    h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Save as candidate'),
      h('button', { type: 'button', onclick: () => { state.form = null; render(); } }, 'Cancel')));
}

async function loadDraft() {
  try {
    state.draft.text = state.candidate
      ? await call('GET', '/v1/candidates/' + state.candidate)
      : await call('GET', '/v1/running');
    state.draft.name = state.candidate || '';
  } catch (e) {
    state.draft.text = '';
  }
  render();
}

function editForm() {
  const check = h('div', null);
  const area = h('textarea', { spellcheck: 'false', 'aria-label': 'Config', oninput: (e) => { state.draft.text = e.target.value; } });
  area.value = state.draft.text;
  const runCheck = async () => {
    try {
      const r = await call('POST', '/v1/check', state.draft.text, 'text/plain');
      check.replaceChildren(h('p', { class: 'change-add' }, 'Valid. ' + r.summary),
        h('ul', { class: 'plain' }, r.describe.map((l) => h('li', null, l))));
    } catch (e) {
      check.replaceChildren(h('pre', { class: 'change-del' }, e.message));
    }
  };
  const save = (e) => {
    e.preventDefault();
    const name = state.draft.name.trim();
    act(() => call('PUT', '/v1/candidates/' + encodeURIComponent(name), state.draft.text, 'text/plain'), () => {
      state.candidate = name;
      state.form = null;
      return 'Saved as candidate ' + name + '. Nothing is applied yet.';
    });
  };
  return h('form', { class: 'panel', onsubmit: save },
    h('h2', null, 'Edit the config'),
    h('p', { class: 'dim' }, 'This is the whole config as text. It starts from ' + (state.candidate ? 'candidate ' + state.candidate : 'the running config') + '. Saving stores a candidate and applies nothing.'),
    area,
    h('div', { class: 'row' },
      field('Candidate name', 'name', state.draft, { required: true, pattern: '[a-z][a-z0-9-]*', placeholder: 'my-change' }),
      h('button', { type: 'button', onclick: runCheck }, 'Check'),
      h('button', { class: 'primary', type: 'submit' }, 'Save as candidate'),
      h('button', { type: 'button', onclick: () => { state.form = null; render(); } }, 'Cancel')),
    check);
}

const commitDraft = { reason: '', window: '300' };

function candidatePanel(pending) {
  const name = state.candidate;
  const plan = state.plan || {};
  const meta = state.meta || {};
  const fourEyes = state.status && state.status.four_eyes;
  const needsApproval = fourEyes && !meta.approved_by;
  const klass = (line) => (line[0] === '+' ? 'change-add' : line[0] === '-' ? 'change-del' : 'change-mod');
  const commit = (e) => {
    e.preventDefault();
    const body = { reason: commitDraft.reason };
    if (commitDraft.window !== 'none') body.confirm_secs = Number(commitDraft.window);
    act(() => call('POST', '/v1/candidates/' + name + '/commit', body),
      (c) => 'Applied commit #' + c.id + (body.confirm_secs ? '. Keep it before the timer runs out, or it undoes itself.' : '.'));
  };
  return [
    h('div', { class: 'panel' },
      h('h2', null, name),
      h('p', { class: 'dim' }, 'Saved by ' + (meta.author || 'unknown') + (meta.saved_at ? ' · ' + when(meta.saved_at) : '')),
      fourEyes ? h('p', null, meta.approved_by
        ? [h('span', { class: 'tag accept' }, 'approved'), ' by ' + meta.approved_by]
        : [h('span', { class: 'tag note' }, 'needs approval'), ' from someone other than ' + (meta.author || 'its author')]) : null,
      plan.error ? h('pre', { class: 'change-del' }, plan.error) : [
        h('p', null, plan.summary || ''),
        plan.first_commit ? h('p', null, 'First commit: there is no running config to compare with.')
          : (plan.changes || []).length
            ? h('ul', { class: 'plain' }, plan.changes.map((c) => h('li', { class: klass(c) }, c)))
            : h('p', { class: 'dim' }, 'No changes against the running config.'),
      ]),
    h('form', { class: 'panel', onsubmit: commit },
      h('h2', null, 'Apply'),
      h('p', { class: 'dim' }, 'With a timer, the change undoes itself unless you keep it. Use one whenever a mistake could cut you off from the box.'),
      h('div', { class: 'fields' },
        field('Reason, such as a ticket', 'reason', commitDraft, { placeholder: 'optional' }),
        h('div', null, h('label', { for: 'f-window' }, 'Undo timer'),
          h('select', { id: 'f-window', onchange: (e) => { commitDraft.window = e.target.value; } },
            [['30', '30 seconds'], ['120', '2 minutes'], ['300', '5 minutes'], ['600', '10 minutes'], ['none', 'No timer']]
              .map(([v, l]) => h('option', { value: v, selected: v === commitDraft.window }, l))))),
      h('div', { class: 'row' },
        may('commit') ? h('button', { class: 'primary', type: 'submit', disabled: pending || needsApproval || !!plan.error }, 'Commit') : null,
        fourEyes && may('approve') && !meta.approved_by
          ? h('button', { type: 'button', onclick: () => act(() => call('POST', '/v1/candidates/' + name + '/approve'), 'Approved ' + name + '.') }, 'Approve') : null,
        may('edit') ? h('button', { type: 'button', onclick: () => { state.form = 'edit'; loadDraft(); } }, 'Edit') : null,
        may('edit') ? h('button', { type: 'button', class: 'danger', onclick: () => act(() => call('DELETE', '/v1/candidates/' + name), 'Deleted candidate ' + name + '.') }, 'Delete') : null),
      pending ? h('p', { class: 'dim' }, 'A commit is waiting to be kept or undone. Deal with that first.') : null),
  ];
}

function explainView() {
  const x = state.explain;
  const names = (state.status && state.status.candidates) || [];
  const go = async (e) => {
    e.preventDefault();
    const body = { src: x.src.trim(), dst: x.dst.trim(), proto: x.proto, in: x.in.trim() };
    if (x.dport) body.dport = Number(x.dport);
    if (x.compare && state.candidate) body.candidate = state.candidate;
    try {
      x.result = await call('POST', '/v1/explain', body);
    } catch (err) {
      x.result = { error: err.message };
    }
    render();
  };
  const ifaces = state.running ? Object.keys(state.running.config.interfaces || {}) : [];
  const side = (title, s) => h('div', { class: 'panel' },
    h('h2', null, title),
    h('p', null, h('span', { class: 'verdict ' + s.verdict }, s.verdict), s.rule ? ' by ' : '', s.rule ? h('span', { class: 'id' }, s.rule) : ''),
    h('pre', null, s.text.split('\n').slice(1).join('\n')));
  const r = x.result;
  return [
    h('form', { class: 'panel', onsubmit: go },
      h('h2', null, 'What happens to this packet?'),
      h('div', { class: 'fields' },
        field('From address', 'src', x, { required: true, placeholder: '192.168.10.50' }),
        field('To address', 'dst', x, { required: true, placeholder: '198.51.100.9' }),
        h('div', null, h('label', { for: 'f-proto' }, 'Protocol'),
          h('select', { id: 'f-proto', onchange: (e) => { x.proto = e.target.value; } },
            ['tcp', 'udp', 'icmp', 'icmpv6'].map((p) => h('option', { value: p, selected: p === x.proto }, p)))),
        field('Port', 'dport', x, { inputmode: 'numeric', placeholder: '443' }),
        field('Arrives on (' + ifaces.concat(['self']).join(', ') + ')', 'in', x, { required: true, placeholder: ifaces[0] || '' })),
      h('div', { class: 'row' },
        h('button', { class: 'primary', type: 'submit' }, 'Explain'),
        names.length ? h('label', null, h('input', { type: 'checkbox', checked: x.compare, onchange: (e) => { x.compare = e.target.checked; }, style: null }), ' also against candidate ' + (state.candidate || names[0])) : null)),
    r && r.error ? h('div', { class: 'panel' }, h('pre', { class: 'change-del' }, r.error)) : null,
    r && !r.error ? h('div', { class: 'grid' },
      r.running ? side('Running config', r.running) : h('div', { class: 'panel' }, 'There is no commit yet, so nothing decides this packet.'),
      r.candidate ? side('Candidate ' + state.candidate, r.candidate) : null) : null,
    r && r.running && r.candidate && r.running.verdict !== r.candidate.verdict
      ? h('div', { class: 'panel' }, 'The candidate changes this packet: ' + r.running.verdict + ' → ' + r.candidate.verdict + '.') : null,
  ];
}

function audit() {
  if (!may('audit')) return h('div', { class: 'panel' }, 'Your role may not read the audit log.');
  return h('div', { class: 'panel' },
    h('h2', null, 'Audit log'),
    h('p', { class: 'dim' }, state.audit.length + ' entries. The daemon checks the hash chain on every read; a changed or missing entry would be reported here instead.'),
    table(['#', 'Time', 'Who', 'Event', 'Detail', 'Hash'],
      state.audit.slice().reverse().map((e) => [e.seq, when(e.time), e.who, e.event, e.detail, h('span', { class: 'id' }, e.hash.slice(0, 10) + '…')])));
}

const tokenDraft = { name: '', role: 'operator', days: '' };

function settings() {
  const s = state.status || {};
  const out = [h('div', { class: 'panel' },
    h('h2', null, 'You'),
    h('p', null, state.me ? state.me.name + ', role ' + state.me.role : ''))];
  out.push(h('div', { class: 'panel' },
    h('h2', null, 'Four-eyes approval'),
    h('p', null, s.four_eyes
      ? 'On. A commit needs approval from someone other than the person who saved the candidate.'
      : 'Off. Anyone who may commit can apply their own candidate.'),
    may('manage') ? h('button', {
      onclick: () => act(() => call('PUT', '/v1/settings', { four_eyes: !s.four_eyes }), 'Four-eyes approval is now ' + (s.four_eyes ? 'off.' : 'on.')),
    }, s.four_eyes ? 'Turn off' : 'Turn on') : h('p', { class: 'dim' }, 'Only an admin can change this.')));
  if (may('manage')) {
    const create = (e) => {
      e.preventDefault();
      const body = { name: tokenDraft.name, role: tokenDraft.role };
      if (tokenDraft.days) body.ttl_secs = Number(tokenDraft.days) * 86400;
      act(() => call('POST', '/v1/tokens', body), (t) => { state.newToken = t; return 'Token ' + t.name + ' created.'; });
    };
    out.push(h('div', { class: 'panel' },
      h('h2', null, 'Access tokens'),
      state.newToken ? h('div', null, h('p', null, 'Secret for ' + state.newToken.name + '. It is shown once and cannot be shown again:'),
        h('p', { class: 'secret mono' }, state.newToken.token)) : null,
      state.tokens.length
        ? table(['Name', 'Role', 'Created', 'By', 'Expires', ''],
          state.tokens.map((t) => [t.name, t.role, when(t.created), t.created_by, t.expires ? when(t.expires) : 'never',
            h('button', { class: 'danger', onclick: () => act(() => call('DELETE', '/v1/tokens/' + t.name), 'Revoked token ' + t.name + '.') }, 'Revoke')]))
        : h('p', { class: 'dim' }, 'No tokens.'),
      h('form', { onsubmit: create },
        h('div', { class: 'fields' },
          field('Name', 'name', tokenDraft, { required: true, pattern: '[a-z][a-z0-9-]*', placeholder: 'laptop' }),
          h('div', null, h('label', { for: 'f-role' }, 'Role'),
            h('select', { id: 'f-role', onchange: (e) => { tokenDraft.role = e.target.value; } },
              ['viewer', 'auditor', 'operator', 'admin'].map((r) => h('option', { value: r, selected: r === tokenDraft.role }, r)))),
          field('Expires after days', 'days', tokenDraft, { inputmode: 'numeric', placeholder: 'never' })),
        h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Create token')))));
  }
  return out;
}

refresh(true);
setInterval(() => { if (state.token) refresh(false); }, 2000);

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
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const state = {
  token: sessionStorage.getItem('ox-token') || '',
  me: null,
  view: 'home',
  home: null,         // the simple view: networks, grid, what is let in
  setup: null,        // first-run setup: { needed, step, code, ports, choice, preview, error }
  back: 'home',       // where a task or a review returns to
  check: { from: '', to: '', what: 'tcp/443', port: '', result: null },
  status: null,
  running: null,      // { config, summary, describe }
  hits: {},           // rule ID -> packets
  leases: [],
  tunnels: [],        // WireGuard tunnels of the running config, with peer state
  vpnDevice: null,    // the config for a device just added; shown once
  hygiene: [],       // findings about rules in the running config
  candidate: null,    // selected candidate name
  meta: null,
  plan: null,
  form: null,         // 'forward' | 'block' | 'edit'
  draft: { name: '', text: '' },
  explain: { src: '', dst: '', proto: 'tcp', dport: '', in: '', compare: true, result: null },
  audit: [],
  tokens: [],
  roles: [],
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

// What the signed-in role may do, as the daemon reports it. The daemon
// checks every request again; this only decides which buttons to show.
function may(action) {
  const can = (state.me && state.me.can) || [];
  if (action === 'read') return true;
  if (action === 'audit') return can.includes('read-audit');
  return can.includes(action);
}

// 'changes only in vpn, network' for a role held to sections, else ''.
function held(role) {
  return role && role.sections ? 'changes only in ' + role.sections.join(', ') : '';
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
  if (!state.token) {
    // A box with no config offers setup in place of sign-in.
    if (!state.setup) {
      state.setup = { needed: false, step: 'code', code: '', ports: [], choice: null, preview: null, error: null };
      try {
        const r = await fetch('/v1/setup');
        state.setup.needed = r.ok && (await r.json()).needed === true;
      } catch (e) { /* the sign-in page still works */ }
    }
    return render();
  }
  try {
    state.me = await call('GET', '/v1/whoami');
    state.status = await call('GET', '/v1/status');
    try {
      state.running = await call('GET', '/v1/running/json');
    } catch (e) {
      if (e.status !== 404) throw e;
      state.running = null;
    }
    state.home = state.running ? await call('GET', '/v1/home').catch(() => null) : null;
    state.hits = parseHits(await call('GET', '/v1/kernel').catch(() => null));
    state.leases = await call('GET', '/v1/leases');
    state.tunnels = await call('GET', '/v1/wireguard').catch(() => []);
    state.hygiene = await call('GET', '/v1/hygiene').catch(() => []);
    const names = state.status.candidates || [];
    if (!names.includes(state.candidate)) state.candidate = names[0] || null;
    if (state.candidate) {
      state.meta = await call('GET', '/v1/candidates/' + state.candidate + '/meta').catch(() => null);
      state.plan = await call('POST', '/v1/candidates/' + state.candidate + '/plan', '').catch((e) => ({ error: e.message }));
    } else {
      state.meta = state.plan = null;
    }
    if (state.view === 'audit' && may('audit')) state.audit = (await call('GET', '/v1/audit')).entries;
    if (state.view === 'admin') state.roles = await call('GET', '/v1/roles');
    if (state.view === 'admin' && may('manage')) state.tokens = await call('GET', '/v1/tokens');
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
  const hasForm = ['home', 'task', 'changes', 'explain', 'admin'].includes(state.view);
  if (rerender || !hasForm) render(); else renderChrome();
}

// ── drawing ─────────────────────────────────────────────────────────────

// Everyone sees these three.
const SIMPLE = [['home', 'Home'], ['access', 'Access'], ['settings', 'Settings']];

// Each advanced feature is a screen that stays out of the way until it is
// switched on in Settings. A switch only shows or hides a screen. It never
// changes what the box does. The choice is kept in this browser.
const ADVANCED = [
  ['rules', 'Rules', 'Full rule list', 'Every rule in order, with sources, services, packet counts and hygiene notes'],
  ['nat', 'NAT', 'Address translation', 'Port forwards and outbound translation, with the rule each one uses'],
  ['network', 'Network', 'Interfaces, DNS and addresses', 'Ports and VLANs, the resolver, address pools, leases and VPN tunnels'],
  ['changes', 'Changes', 'Candidates and the config editor', 'Named candidates, the full plan, the whole config as text, approvals'],
  ['explain', 'Explain', 'Packet tracer', 'Follow one packet step by step, against the running config and a candidate'],
  ['audit', 'Audit', 'Audit log', 'Every change with who made it, in a hash-chained log'],
  ['admin', 'Admin', 'Access tokens and roles', 'Tokens, roles, four-eyes approval, and managing this box from another machine'],
];

function chosenAdvanced() {
  try { return JSON.parse(localStorage.getItem('ox-advanced') || '[]'); } catch (e) { return []; }
}

// A feature the box already depends on shows its screen whatever the switch says.
function inUse(id) {
  const cells = (state.home && state.home.cells) || [];
  if (id === 'rules') return cells.some((row) => row.some((c) => c.state === 'custom'));
  if (id === 'changes') return !!(state.status && state.status.four_eyes);
  return false;
}

function shown(id) {
  if (id === 'audit' && !may('audit')) return false;
  return inUse(id) || chosenAdvanced().includes(id);
}

function setAdvanced(id, on) {
  const now = chosenAdvanced().filter((x) => x !== id);
  if (on) now.push(id);
  localStorage.setItem('ox-advanced', JSON.stringify(now));
  render();
}

function go(view) {
  state.view = view;
  state.notice = null;
  state.form = null;
  refresh(true);
}

function chrome() {
  const s = state.status || {};
  const run = s.running;
  const waiting = (s.candidates || []).length;
  const top = h('header', { class: 'top' },
    h('span', { class: 'brand' }, 'Netoxide'),
    h('span', { class: 'fact' }, h('b', null, state.running ? state.running.config.hostname : 'not set up')),
    s.applier && s.applier !== 'kernel' ? h('span', { class: 'tag note' }, 'dry run: nothing is loaded') : null,
    waiting ? h('button', { class: 'link', onclick: () => review(s.candidates[0], state.view) },
      waiting + ' change' + (waiting === 1 ? '' : 's') + ' waiting') : null,
    h('span', { class: 'spacer' }),
    state.me ? h('span', { class: 'fact' }, state.me.name) : null,
    h('button', { onclick: signOut }, 'Sign out'));

  const tabs = SIMPLE.concat(ADVANCED.filter(([id]) => shown(id)).map(([id, label]) => [id, label]));
  const nav = h('nav', null, tabs.map(([id, label]) => h('button', {
    class: state.view === id ? 'on' : '',
    onclick: () => go(id),
  }, label)));

  const banners = [];
  if (state.problem) banners.push(h('div', { class: 'banner bad' }, 'Cannot read the box: ' + state.problem));
  if (s.reverts_in != null && run) {
    banners.push(h('div', { class: 'banner warn' },
      h('span', { class: 'grow' }, 'Your change is applied. Check things still work. It undoes itself in ' + mmss(s.reverts_in) + ' unless you keep it.'),
      may('commit') ? h('button', { class: 'primary', onclick: () => act(() => call('POST', '/v1/confirm'), 'Kept. The change is now permanent.') }, 'Keep it') : null,
      may('commit') ? h('button', { class: 'danger', onclick: () => act(() => call('POST', '/v1/revert'), 'Undone. The box is as it was before.') }, 'Undo now') : null));
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
    app.replaceChildren(state.setup && state.setup.needed ? setupView() : signIn());
    return;
  }
  const views = { home, access, settings, task, review: reviewView, rules, nat, network, changes, explain: explainView, audit, admin };
  // A screen that was switched off, or one this role may not see, falls back to Home.
  const wanted = ADVANCED.some(([id]) => id === state.view) && !shown(state.view) ? 'home' : state.view;
  const draw = views[wanted] || home;
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
    h('p', { class: 'dim' }, 'Sign in with an access token. Whoever set this box up has one. A new one is made on the box with ',
      h('code', null, 'ox token create <name> --role operator'), '.'),
    state.problem ? h('p', { class: 'change-del' }, state.problem) : null,
    h('label', { for: 'token' }, 'Access token'),
    Object.assign(input, { id: 'token' }),
    h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Sign in')));
}

function signOut() {
  state.token = '';
  state.me = null;
  state.setup = null;
  sessionStorage.removeItem('ox-token');
  refresh(true);
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
    h('p', { class: 'dim' }, 'On the box, run ', h('code', null, 'ox init --save starter'), ' then ', h('code', null, 'ox commit starter --confirm 5m'), '.'));
}

// ── first-run setup ─────────────────────────────────────────────────────

async function setupCall(method, path, body) {
  const headers = { 'X-Setup-Code': state.setup.code };
  if (body) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ('the box answered ' + res.status));
  return data;
}

function setupChoice() {
  const c = state.setup.choice;
  return {
    internet: c.internet,
    name: c.name,
    inside: Object.keys(c.inside).filter((p) => c.inside[p] && p !== c.internet)
      .map((port) => (c.address[port] ? { port, address: c.address[port] } : { port })),
  };
}

function setupView() {
  const su = state.setup;
  const fail = (e) => { su.error = e.message; render(); };
  const steps = h('p', { class: 'dim' }, 'Step ' + ({ code: 1, ports: 2, review: 3 }[su.step]) + ' of 3');
  const problem = su.error ? h('p', { class: 'change-del', role: 'alert' }, su.error) : null;

  if (su.step === 'code') {
    const next = async (e) => {
      e.preventDefault();
      su.error = null;
      try {
        const r = await setupCall('GET', '/v1/setup/ports');
        su.ports = r.ports;
        const internet = (r.ports.find((p) => p.internet) || r.ports[0] || {}).name || '';
        const inside = {};
        for (const p of r.ports) inside[p.name] = p.name !== internet && r.ports.length <= 2;
        su.choice = { internet, inside, address: {}, name: r.hostname };
        su.step = 'ports';
        render();
      } catch (err) { fail(err); }
    };
    return h('form', { class: 'panel signin', onsubmit: next },
      h('h1', null, 'Set up this box'), steps,
      h('p', null, 'This box has no config yet. To prove you are the person setting it up, enter the setup code.'),
      h('p', { class: 'dim' }, 'The code is shown on the box itself: run ', h('code', null, 'ox status'), ' there, or read the line the daemon printed when it started.'),
      problem,
      field('Setup code', 'code', su, { required: true, placeholder: 'ABCD-EFGH', autocomplete: 'off', autocapitalize: 'characters' }),
      h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Continue')),
      h('p', { class: 'dim' }, 'Already set up? ', h('button', { type: 'button', class: 'link', onclick: () => { su.needed = false; render(); } }, 'Sign in with a token')));
  }

  const c = su.choice;
  if (su.step === 'ports') {
    const next = async (e) => {
      e.preventDefault();
      su.error = null;
      try {
        su.preview = (await setupCall('POST', '/v1/setup/preview', setupChoice())).describe;
        su.step = 'review';
        render();
      } catch (err) { fail(err); }
    };
    const about = (p) => (p.up ? 'connected' : 'nothing plugged in') + (p.addresses.length ? ', has ' + p.addresses.join(', ') : ', no address yet');
    return h('form', { class: 'panel setup', onsubmit: next },
      h('h1', null, 'Set up this box'), steps, problem,
      h('h2', null, 'Which port goes to the internet?'),
      h('p', { class: 'dim' }, 'The one plugged into your modem or your provider. Everything arriving there is blocked unless you later let something in.'),
      su.ports.map((p) => h('div', { class: 'check' },
        h('input', { type: 'radio', name: 'internet', id: 'wan-' + p.name, checked: c.internet === p.name, onchange: () => { c.internet = p.name; c.inside[p.name] = false; render(); } }),
        h('label', { for: 'wan-' + p.name }, h('b', null, p.name), ' ', h('span', { class: 'dim' }, about(p) + (p.internet ? ', reaches the internet now' : ''))))),
      h('h2', null, 'Which ports are your own network?'),
      h('p', { class: 'dim' }, 'Devices there get an address and DNS from the box and can reach the internet.'),
      su.ports.length < 2 ? h('p', { class: 'change-del', role: 'alert' },
        'This machine has only one network port. A router needs two: one to the internet and one to your own network. Add a port, or a second virtual port if this is a virtual machine, then start again.') : null,
      su.ports.filter((p) => p.name !== c.internet).map((p) => h('div', null,
        h('div', { class: 'check' },
          h('input', { type: 'checkbox', id: 'lan-' + p.name, checked: !!c.inside[p.name], onchange: (e) => { c.inside[p.name] = e.target.checked; render(); } }),
          h('label', { for: 'lan-' + p.name }, h('b', null, p.name), ' ', h('span', { class: 'dim' }, about(p)))),
        c.inside[p.name] ? h('div', { class: 'indent' },
          field("The box's address on " + p.name, p.name, c.address, { placeholder: p.addresses[0] || '192.168.10.1/24' }),
          h('p', { class: 'dim' }, p.addresses.length
            ? 'Leave it empty to keep the address the port has now. That is the safe choice if you are connected through this port.'
            : 'Leave it empty to use 192.168.10.1/24.')) : null)),
      h('h2', null, 'A name for the box'),
      field('Name', 'name', c, { required: true, pattern: '[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?', placeholder: 'homebox' }),
      h('div', { class: 'row' },
        h('button', { class: 'primary', type: 'submit', disabled: !su.ports.some((p) => p.name !== c.internet && c.inside[p.name]) }, 'Review'),
        h('button', { type: 'button', onclick: () => { su.step = 'code'; render(); } }, 'Back')));
  }

  const apply = async () => {
    su.error = null;
    try {
      const r = await setupCall('POST', '/v1/setup/apply', setupChoice());
      state.token = r.token;
      sessionStorage.setItem('ox-token', r.token);
      state.newToken = { name: 'setup', token: r.token };
      state.view = 'home';
      state.notice = { kind: 'ok', text: 'The box is set up. Check your connection still works, then keep the change.' };
      refresh(true);
    } catch (err) { fail(err); }
  };
  return h('div', { class: 'panel setup' },
    h('h1', null, 'Set up this box'), steps, problem,
    h('h2', null, 'This is what the box will do'),
    h('ul', { class: 'plain' }, su.preview.map((l) => h('li', null, l))),
    h('h2', null, 'Applied safely'),
    h('p', null, 'You get 5 minutes to check that things still work. If you cannot reach this page afterwards, do nothing: the box undoes the setup by itself and you can start again with the same code.'),
    h('div', { class: 'row' },
      h('button', { class: 'primary', onclick: apply }, 'Apply safely'),
      h('button', { onclick: () => { su.step = 'ports'; render(); } }, 'Back')));
}

// ── the simple layer ────────────────────────────────────────────────────

// Opens the review of one waiting change. `back` is where to return to.
function review(name, back) {
  state.candidate = name;
  state.back = ['task', 'review'].includes(back) ? 'home' : back || 'home';
  go('review');
}

// Starts one of the plain-language tasks.
function startTask(form) {
  state.back = state.view === 'task' ? state.back : state.view;
  state.view = 'task';
  state.notice = null;
  state.form = form;
  render();
}

function task() {
  const forms = { forward: forwardForm, block: blockForm, vpn: vpnForm, network: networkForm };
  return [vpnDevicePanel(), (forms[state.form] || forwardForm)()];
}

const TASKS = [
  ['network', 'Add a network, such as one for guests'],
  ['forward', 'Let something in from the internet'],
  ['vpn', 'Give a phone or laptop remote access'],
  ['block', 'Block a device or a website'],
];

// The name someone gave a rule or a port forward, by its ID.
function ruleName(id) {
  const c = (state.running && state.running.config) || {};
  for (const p of c.policy || []) for (const r of p.rule || []) if (r.id === id) return r.name;
  for (const f of (c.nat && c.nat.forward) || []) if (f.id === id || f.rule === id) return f.name;
  return null;
}

// Setup made a token and it is shown once. Losing it locks the owner out
// of this page, so it stays in view until they say it is saved.
function tokenPanel() {
  const t = state.newToken;
  if (!t || t.name !== 'setup') return null;
  return h('div', { class: 'panel waiting' },
    h('h2', null, 'Save your access token now'),
    h('p', null, 'Setup made this token for you. It is how you sign in next time, and it is not shown again. Put it in your password manager.'),
    h('p', { class: 'secret mono' }, t.token),
    h('div', { class: 'row' }, h('button', { onclick: () => { state.newToken = null; render(); } }, 'I have saved it')));
}

function waitingPanel() {
  const names = (state.status && state.status.candidates) || [];
  if (!names.length) return null;
  return h('div', { class: 'panel waiting' },
    h('h2', null, names.length === 1 ? 'A change is waiting' : names.length + ' changes are waiting'),
    h('p', { class: 'dim' }, 'Nothing is applied until you review it.'),
    names.map((n) => h('div', { class: 'row' },
      h('span', { class: 'grow' }, n),
      h('button', { class: 'primary', onclick: () => review(n, state.view) }, 'Review and apply'))));
}

function home() {
  const s = state.status || {};
  if (!state.running) {
    return [waitingPanel(), h('div', { class: 'panel' },
      h('h2', null, 'This box is not set up yet'),
      h('p', null, 'Nothing is running, so the box filters nothing and routes nothing.'),
      h('p', { class: 'dim' }, 'On the box, run ', h('code', null, 'ox init --save starter'), ' then ', h('code', null, 'ox commit starter --confirm 5m'), '.'))];
  }
  const hm = state.home || { networks: [], cells: [], let_in: [], devices: [] };
  const dry = s.applier && s.applier !== 'kernel';
  const pending = s.reverts_in != null;
  const services = (s.services || []);
  const trouble = services.filter(([, st]) => !/running|bound|has /.test(st));
  const headline = dry ? ['note', 'Dry run', 'The box keeps its config and answers here, and loads nothing into the kernel.']
    : pending ? ['note', 'A change is waiting for you to keep it', 'Use the bar at the top to keep it or undo it.']
      : trouble.length ? ['note', 'The firewall is running, and something needs a look', trouble.map(([n, st]) => n + ': ' + st).join('; ')]
        : ['accept', 'The firewall is running', 'Nothing needs you right now.'];
  const inside = hm.networks.map((n, i) => [n, hm.devices[i] || 0]).filter(([n]) => !n.internet);
  const x = state.check;
  const runCheck = async (e) => {
    e.preventDefault();
    const [proto, port] = x.what === 'other' ? ['tcp', x.port] : x.what.split('/');
    const body = { src: x.from.trim(), dst: x.to.trim(), proto };
    if (port) body.dport = Number(port);
    try { x.result = await call('POST', '/v1/explain', body); } catch (err) { x.result = { error: err.message }; }
    render();
  };
  const answer = () => {
    const r = x.result;
    if (!r) return null;
    if (r.error) return h('p', { class: 'change-del', role: 'alert' }, r.error);
    const run = r.running;
    const okay = run.verdict === 'ACCEPT';
    const named = run.rule ? ruleName(run.rule) : null;
    const why = run.rule
      ? (okay ? 'It is allowed by ' : 'It is stopped by ') + (named ? '"' + named + '"' : 'rule ' + run.rule) + '.'
      : (okay ? 'Nothing stands in its way.' : 'Nothing allows it, and anything not allowed is blocked.');
    return h('div', { class: 'answer' },
      h('p', null, h('span', { class: 'tag ' + (okay ? 'accept' : 'drop') }, okay ? 'Allowed' : 'Blocked'), ' ', why),
      h('details', null, h('summary', null, 'How the box decided'),
        h('pre', { class: 'dim' }, run.text.split('\n').slice(1).join('\n')),
        shown('explain') ? null : h('p', { class: 'dim' }, 'To compare with a waiting change, turn on the packet tracer in Settings.')));
  };

  return [
    tokenPanel(),
    waitingPanel(),
    h('div', { class: 'panel status' },
      h('h2', null, h('span', { class: 'tag ' + headline[0] }, headline[0] === 'accept' ? '✓' : '!'), ' ', headline[1]),
      h('p', { class: 'dim' }, headline[2]),
      h('div', { class: 'grid facts' },
        h('div', null, h('b', null, 'From the internet'),
          h('p', { class: 'dim' }, hm.let_in.length
            ? hm.let_in.length + ' thing' + (hm.let_in.length === 1 ? ' is' : 's are') + ' let in. Everything else is blocked.'
            : 'Everything is blocked. Nothing is let in.')),
        h('div', null, h('b', null, 'Changes'),
          h('p', { class: 'dim' }, 'Applied safely: each one undoes itself after 2 minutes unless you keep it.')),
        h('div', null, h('b', null, 'Services'),
          h('p', { class: 'dim' }, services.length ? services.map(([n, st]) => n + ': ' + st).join('; ') : 'The box hands out no addresses and answers no DNS.')))),
    h('div', { class: 'grid' }, inside.map(([n, devices]) => h('div', { class: 'panel' },
      h('h2', null, n.name),
      h('p', null, devices + ' device' + (devices === 1 ? '' : 's') + ' with an address from the box'),
      h('p', { class: 'dim' }, 'Can reach: ' + n.reaches),
      h('p', { class: 'dim' }, n.interfaces.join(', ') + (n.addresses.length ? ' · ' + n.addresses.join(', ') : ''))))),
    h('div', { class: 'grid' },
      h('form', { class: 'panel', onsubmit: runCheck },
        h('h2', null, 'Is something blocked?'),
        h('p', { class: 'dim' }, 'Say which device is trying to reach what, and the box says what it would do and why.'),
        h('div', { class: 'fields' },
          field('From (address of the device)', 'from', x, { required: true, placeholder: '192.168.10.50' }),
          field('To (address)', 'to', x, { required: true, placeholder: '1.1.1.1' }),
          h('div', null, h('label', { for: 'f-what' }, 'Using'),
            h('select', { id: 'f-what', onchange: (e) => { x.what = e.target.value; render(); } },
              [['tcp/443', 'Secure web (HTTPS)'], ['tcp/80', 'Web (HTTP)'], ['udp/53', 'DNS'], ['tcp/22', 'SSH'], ['icmp/', 'Ping'], ['other', 'Another TCP port']]
                .map(([v, l]) => h('option', { value: v, selected: v === x.what }, l)))),
          x.what === 'other' ? field('Port', 'port', x, { required: true, inputmode: 'numeric', placeholder: '8080' }) : null),
        h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Check')),
        answer()),
      may('edit') ? h('div', { class: 'panel list' },
        h('h2', null, 'Common tasks'),
        TASKS.map(([form, label]) => h('button', { onclick: () => startTask(form) }, label)),
        h('button', { onclick: () => go('access') }, 'Change which networks can reach each other')) : null),
    h('details', { class: 'panel' },
      h('summary', null, 'Everything this box does, line by line'),
      h('ul', { class: 'plain' }, state.running.describe.map((line) => h('li', null, line)))),
  ];
}

function access() {
  if (!state.running || !state.home) return noConfig();
  const hm = state.home;
  const pending = state.status && state.status.reverts_in != null;
  const flip = (from, to, allow) => act(
    () => call('POST', '/v1/actions/access', { from: from.zone, to: to.zone, allow }),
    (r) => { review(r.candidate, 'access'); return r.done.join('. ') + '. Nothing is applied yet.'; });
  const cell = (from, to, c) => {
    if (c.state === 'same') return h('span', { class: 'dim' }, from.internet ? '—' : 'same network');
    if (c.state === 'custom') {
      return h('span', null, h('span', { class: 'tag note' }, c.summary), ' ',
        shown('rules') ? h('button', { class: 'link', onclick: () => go('rules') }, 'see rules') : null);
    }
    const allowed = c.state === 'allowed';
    const label = h('span', { class: 'tag ' + (allowed ? 'accept' : 'drop') }, allowed ? 'Allowed' : 'Blocked');
    // The internet is let in one service at a time, below.
    if (from.internet || !may('edit') || pending) return label;
    return h('span', null, label, ' ',
      h('button', { class: 'link', 'aria-label': (allowed ? 'Block ' : 'Allow ') + from.name + ' to ' + to.name, onclick: () => flip(from, to, !allowed) },
        allowed ? 'block' : 'allow'));
  };
  const custom = hm.cells.some((row) => row.some((c) => c.state === 'custom'));
  return [
    waitingPanel(),
    h('div', { class: 'panel' },
      h('h2', null, 'Who can reach what'),
      h('p', { class: 'dim' }, 'Read across: the network on the left may reach the networks along the top. Anything not allowed is blocked and logged.'),
      table([{ label: 'From ↓  can reach →' }].concat(hm.networks.map((n) => n.name)),
        hm.networks.map((from, i) => [h('b', null, from.name)].concat(hm.networks.map((to, j) => cell(from, to, hm.cells[i][j]))))),
      custom ? h('p', { class: 'dim' }, 'A yellow cell has rules of its own, for particular devices or services. Those are edited as rules, not here, so nothing is changed by accident.',
        shown('rules') ? '' : ' Turn on the full rule list in Settings to see them.') : null,
      pending ? h('p', { class: 'dim' }, 'A change is waiting to be kept or undone. Deal with that first.') : null),
    h('div', { class: 'panel' },
      h('h2', null, 'Let in from the internet'),
      hm.let_in.length
        ? table(['What', 'Outside port', 'Goes to'], hm.let_in.map((f) => [f.name, f.service, f.to]))
        : h('p', { class: 'dim' }, 'Nothing. Everything arriving from the internet is blocked.'),
      may('edit') ? h('div', { class: 'row' },
        h('button', { onclick: () => startTask('network') }, 'Add a network'),
        h('button', { onclick: () => startTask('forward') }, 'Let something in'),
        h('button', { onclick: () => startTask('vpn') }, 'Give a phone or laptop remote access'),
        h('button', { onclick: () => startTask('block') }, 'Block a device or a website')) : null),
  ];
}

// One waiting change, in sentences, with one safe way to apply it.
function reviewView() {
  const name = state.candidate;
  const s = state.status || {};
  if (!name || !(s.candidates || []).includes(name)) {
    return h('div', { class: 'panel' }, h('p', null, 'Nothing is waiting.'),
      h('div', { class: 'row' }, h('button', { onclick: () => go(state.back) }, 'Back')));
  }
  const plan = state.plan || {};
  const meta = state.meta || {};
  const pending = s.reverts_in != null;
  const needsApproval = s.four_eyes && !meta.approved_by;
  const apply = () => act(
    () => call('POST', '/v1/candidates/' + name + '/commit', { reason: '', confirm_secs: 120 }),
    () => { state.view = state.back; return 'Applied. Check things still work, then keep it.'; });
  const discard = () => act(() => call('DELETE', '/v1/candidates/' + name),
    () => { state.view = state.back; return 'Discarded. Nothing was changed.'; });
  const list = (title, lines, klass) => (lines && lines.length
    ? h('div', null, h('h3', null, title), h('ul', { class: 'plain' }, lines.map((l) => h('li', { class: klass }, l)))) : null);
  const nothing = !plan.error && !plan.first_commit && !(plan.starts || []).length && !(plan.stops || []).length;
  return [
    vpnDevicePanel(),
    h('div', { class: 'panel' },
      h('h2', null, 'What will change'),
      h('p', { class: 'dim' }, (meta.author ? 'Prepared by ' + meta.author : '') + (meta.saved_at ? ' · ' + when(meta.saved_at) : '')),
      plan.error ? h('pre', { class: 'change-del' }, plan.error) : null,
      plan.first_commit ? h('p', null, 'This is the first config for the box.') : null,
      (plan.headline || []).length ? h('ul', { class: 'plain headline' }, plan.headline.map((l) => h('li', null, l))) : null,
      (plan.starts || []).length || (plan.stops || []).length ? h((plan.headline || []).length ? 'details' : 'div', null,
        (plan.headline || []).length ? h('summary', null, 'In detail') : null,
        list('The box will start doing this', plan.starts, 'change-add'),
        list('The box will stop doing this', plan.stops, 'change-del')) : null,
      nothing ? h('p', { class: 'dim' }, (plan.changes || []).length
        ? 'This changes details that have no plain sentence: ' + plan.changes.join('; ')
        : 'Nothing. This is the same as what the box does now.') : null,
      shown('changes') ? h('p', null, h('button', { class: 'link', onclick: () => go('changes') }, 'See the full plan and the config')) : null),
    h('div', { class: 'panel' },
      h('h2', null, 'Apply safely'),
      h('p', null, 'You get 2 minutes to check things still work. If you do not keep the change, it undoes itself, so a mistake cannot lock you out.'),
      needsApproval ? h('p', null, h('span', { class: 'tag note' }, 'needs approval'), ' from someone other than ' + (meta.author || 'its author') + '.') : null,
      pending ? h('p', { class: 'dim' }, 'Another change is waiting to be kept or undone. Deal with that first.') : null,
      h('div', { class: 'row' },
        may('commit') ? h('button', { class: 'primary', disabled: pending || needsApproval || !!plan.error, onclick: apply }, 'Apply safely') : null,
        needsApproval && may('approve') ? h('button', { onclick: () => act(() => call('POST', '/v1/candidates/' + name + '/approve'), 'Approved.') }, 'Approve') : null,
        may('edit') ? h('button', { class: 'danger', onclick: discard }, 'Discard') : null,
        h('button', { onclick: () => go(state.back) }, 'Not now'))),
  ];
}

function settings() {
  const s = state.status || {};
  const me = state.me || {};
  return [
    h('div', { class: 'panel' },
      h('h2', null, 'Basics'),
      table(['', ''], [
        ['Box name', state.running ? state.running.config.hostname : 'not set up'],
        ['Signed in as', (me.name || '') + (me.role ? ', role ' + me.role : '') + (me.sections ? ' (' + held(me) + ')' : '')],
        ['Changes', 'Applied safely: each one undoes itself after 2 minutes unless you keep it'],
        ['Second approval', s.four_eyes ? 'On: a change needs approval from a second person' : 'Off'],
        ['Version', s.version || ''],
      ])),
    tokenPanel(),
    h('div', { class: 'panel' },
      h('h2', null, 'Advanced features'),
      h('p', { class: 'dim' }, 'Each adds its own tab. Turning one off hides its screen and never changes what the box does. A feature the box already depends on stays on. The choice is kept in this browser.'),
      ADVANCED.filter(([id]) => id !== 'audit' || may('audit')).map(([id, , title, about]) => h('div', { class: 'check switch' },
        h('input', { type: 'checkbox', id: 'adv-' + id, checked: shown(id), disabled: inUse(id), onchange: (e) => setAdvanced(id, e.target.checked) }),
        h('label', { for: 'adv-' + id }, h('b', null, title), inUse(id) ? h('span', { class: 'tag note' }, 'in use') : null,
          h('span', { class: 'dim' }, about))))),
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
        [r.name, r.enabled === false ? h('span', { class: 'tag note' }, 'disabled') : null,
          r.reason ? h('div', { class: 'dim' }, r.reason) : null,
          state.hygiene.filter((f) => f.rule === r.id).map((f) => h('div', null, h('span', { class: 'tag note' }, f.kind), ' ', h('span', { class: 'dim' }, f.detail)))],
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
          n.forward.map((f) => [h('span', { class: 'id' }, f.id), f.name, f.from, (f.address || "the box's own address") + ' ' + f.service,
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
  for (const t of state.tunnels) {
    const now = Date.now() / 1000;
    out.push(h('div', { class: 'panel' },
      h('h2', null, 'VPN tunnel ' + t.name),
      h('p', null, 'Zone ' + t.zone + ', ' + (t.addresses || []).join(', ') +
        (t.listen_port ? ', listening on udp/' + t.listen_port + '.' : ', connects out only.')),
      h('p', null, "This box's public key: ", h('code', null, t.public_key)),
      t.peers.length
        ? table(['Peer', 'State', 'May use', { label: 'Received', num: true }, { label: 'Sent', num: true }],
          t.peers.map((p) => [h('b', null, p.name),
            !p.last_handshake ? h('span', { class: 'dim' }, 'never connected')
              : now - p.last_handshake < 180 ? h('span', { class: 'tag accept' }, 'connected')
                : 'last heard from ' + when(p.last_handshake),
            (p.allowed || []).join(', '), size(p.rx_bytes), size(p.tx_bytes)]))
        : h('p', { class: 'dim' }, 'No peers yet.')));
  }
  return out;
}

function size(n) {
  if (!n) return '0';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
  return (i ? n.toFixed(1) : n) + ' ' + units[i];
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
      h('button', { onclick: open('vpn'), disabled: !state.running }, 'Add a VPN device'),
      h('button', { onclick: () => { state.draft = { name: '', text: '' }; state.form = 'edit'; loadDraft(); } }, 'Edit the config'),
    ] : null);

  let right;
  if (state.form === 'forward') right = forwardForm();
  else if (state.form === 'block') right = blockForm();
  else if (state.form === 'vpn') right = vpnForm();
  else if (state.form === 'edit') right = editForm();
  else if (state.candidate) right = candidatePanel(pending);
  else {
    const run = state.status && state.status.running;
    right = h('div', { class: 'panel' },
      h('p', { class: 'dim' }, 'Choose a candidate, or start a new change.'),
      run ? [h('h2', null, 'Running'),
        h('p', null, h('b', null, 'Commit #' + run.id), run.state === 'pending' ? ' (not yet kept)' : ''),
        h('p', { class: 'dim' }, 'by ' + run.author + ' · ' + when(run.time)),
        h('p', { class: 'dim' }, run.source + (run.reason ? ' · ' + run.reason : '')),
        h('p', { class: 'dim' }, state.running ? state.running.summary : '')] : null);
  }
  return h('div', { class: 'split' }, left, h('div', null, vpnDevicePanel(), right));
}

// The config for a device that was just added. It holds the device's
// private key, which the box does not keep, so it stays until dismissed
// and is gone on reload.
function vpnDevicePanel() {
  const d = state.vpnDevice;
  if (!d) return null;
  return h('div', { class: 'panel' },
    h('h2', null, 'Config for ' + d.name),
    h('p', null, 'Import this into the WireGuard app on the device. The device connects once the candidate is committed.'),
    h('pre', { class: 'secret' }, d.config),
    d.qr ? h('div', null,
      h('p', null, 'For a phone, scan this in the WireGuard app:'),
      h('div', { class: 'qr', role: 'img', 'aria-label': 'QR code of the config for ' + d.name },
        d.qr.map((row) => h('div', null, [...row].map((c) => h('span', { class: c === '1' ? 'on' : '' })))))) : null,
    h('p', { class: 'dim' }, d.made
      ? "This is the only copy of the device's private key. The box does not keep it."
      : "Put the device's own private key in place of the placeholder."),
    h('div', { class: 'row' }, h('button', { onclick: () => { state.vpnDevice = null; render(); } }, 'I have saved it')));
}

const draftForward = { name: '', port: 'tcp/443', to: '', to_port: '', address: '' };
const draftBlock = { address: '', name: '' };
const draftVpn = { name: '', endpoint: '', public_key: '' };
const draftNetwork = { name: '', port: '', vlan: '', address: '', internet: true };

function saved(result) {
  const fromTask = state.view === 'task';
  state.candidate = result.candidate;
  state.form = null;
  // A plain task leads straight to its review. The advanced screen stays put.
  if (fromTask) state.view = 'review';
  return result.done.join('; ') + '. ' + (fromTask ? 'Nothing is applied yet.' : 'Saved as candidate ' + result.candidate + '. Nothing is applied yet.');
}

// Leaves a task form: back to where it was started from.
function cancelTask() {
  if (state.view === 'task') return go(state.back);
  state.form = null;
  render();
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
      field('Outside address, if the box has several', 'address', draftForward, { placeholder: "whichever the box has" })),
    h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Review'),
      h('button', { type: 'button', onclick: cancelTask }, 'Cancel')));
}

function blockForm() {
  // An address means a device. Anything else is taken as a website's name.
  const isDevice = (v) => /^[0-9a-fA-F:.]+(\/[0-9]+)?$/.test(v.trim()) && /[.:]/.test(v) && !/[g-zG-Z]/.test(v);
  const go = (e) => {
    e.preventDefault();
    const what = draftBlock.address.trim();
    act(() => (isDevice(what)
      ? call('POST', '/v1/actions/block', { address: what, name: draftBlock.name })
      : call('POST', '/v1/actions/block-site', { name: what, block: true })), saved);
  };
  const sites = ((state.running && state.running.config.dns) || {}).blocked || [];
  return [h('form', { class: 'panel', onsubmit: go },
    h('h2', null, 'Block a device or a website'),
    h('p', { class: 'dim' }, 'Give the address of a device to drop everything it sends, to other networks and to the box. Or give the name of a website to stop every device looking it up.'),
    h('div', { class: 'fields' },
      field('Device address or website name', 'address', draftBlock, { required: true, placeholder: '192.168.10.66 or example.com' }),
      field('For a device: what is it?', 'name', draftBlock, { placeholder: 'Smart TV' })),
    h('p', { class: 'dim' }, 'A website block works through the box\'s DNS. A device set to use another DNS server, or a browser with its own secure DNS turned on, is not affected.'),
    h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Review'),
      h('button', { type: 'button', onclick: cancelTask }, 'Cancel'))),
  sites.length ? h('div', { class: 'panel' },
    h('h2', null, 'Blocked websites'),
    table(['Name', ''], sites.map((n) => [n,
      h('button', { 'aria-label': 'Unblock ' + n, onclick: () => act(() => call('POST', '/v1/actions/block-site', { name: n, block: false }), saved) }, 'Unblock')]))) : null];
}

function networkForm() {
  // An inside port that is a real port: not the internet side, not a VLAN.
  const ifaces = Object.entries((state.running && state.running.config.interfaces) || {})
    .filter(([, i]) => !i.default_route && !i.vlan).map(([name]) => name);
  if (!ifaces.includes(draftNetwork.port)) draftNetwork.port = ifaces[0] || '';
  const go = (e) => {
    e.preventDefault();
    const body = { name: draftNetwork.name, port: draftNetwork.port, vlan: Number(draftNetwork.vlan), internet: draftNetwork.internet };
    if (draftNetwork.address) body.address = draftNetwork.address;
    act(() => call('POST', '/v1/actions/network', body), (r) => { draftNetwork.name = ''; draftNetwork.vlan = ''; draftNetwork.address = ''; return saved(r); });
  };
  return h('form', { class: 'panel', onsubmit: go },
    h('h2', null, 'Add a network'),
    h('p', { class: 'dim' }, 'A network of its own for guests, cameras or anything you want kept apart. Devices on it get an address and DNS from the box. It reaches none of your other networks, and they do not reach it, until you allow that under Access.'),
    h('div', { class: 'fields' },
      field('What is it for?', 'name', draftNetwork, { required: true, maxlength: '40', placeholder: 'Guest Wi-Fi' }),
      h('div', null, h('label', { for: 'f-port' }, 'On which port?'),
        h('select', { id: 'f-port', onchange: (e) => { draftNetwork.port = e.target.value; } },
          ifaces.map((n) => h('option', { value: n, selected: n === draftNetwork.port }, n)))),
      field('VLAN number', 'vlan', draftNetwork, { required: true, inputmode: 'numeric', pattern: '[0-9]{1,4}', placeholder: '20' }),
      field("The box's address on it", 'address', draftNetwork, { placeholder: 'chosen for you' })),
    h('div', { class: 'check' },
      h('input', { type: 'checkbox', id: 'f-internet', checked: draftNetwork.internet, onchange: (e) => { draftNetwork.internet = e.target.checked; } }),
      h('label', { for: 'f-internet' }, 'Devices on it can reach the internet')),
    h('p', { class: 'dim' }, 'The network travels on that port as a VLAN. Set the switch or access point there to use the same VLAN number for it.'),
    h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit', disabled: !ifaces.length }, 'Review'),
      h('button', { type: 'button', onclick: cancelTask }, 'Cancel')));
}

function vpnForm() {
  const go = (e) => {
    e.preventDefault();
    const body = { name: draftVpn.name, endpoint: draftVpn.endpoint };
    if (draftVpn.public_key) body.public_key = draftVpn.public_key;
    act(() => call('POST', '/v1/actions/vpn-peer', body), (result) => {
      state.vpnDevice = { name: draftVpn.name, config: result.client_config, made: result.key_made_here, qr: result.qr };
      draftVpn.name = '';
      draftVpn.public_key = '';
      return saved(result);
    });
  };
  return h('form', { class: 'panel', onsubmit: go },
    h('h2', null, 'Add a VPN device'),
    h('p', { class: 'dim' }, 'Lets a phone or laptop reach the inside network from anywhere, over WireGuard. The first device also sets the VPN up: the tunnel, the rule that lets devices connect, and the rules for what they may reach.'),
    h('div', { class: 'fields' },
      field('What is it?', 'name', draftVpn, { required: true, placeholder: 'laptop' }),
      field('How the device finds this box from outside', 'endpoint', draftVpn, { required: true, placeholder: 'home.example.net' }),
      field("The device's public key, if it made its own", 'public_key', draftVpn, { placeholder: 'make one for it' })),
    h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Review'),
      h('button', { type: 'button', onclick: cancelTask }, 'Cancel')));
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

const commitDraft = { reason: '', window: '120' };

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
const ACTIONS = [
  ['read-audit', 'Read the audit log'],
  ['edit', 'Save and delete candidates'],
  ['approve', 'Approve candidates'],
  ['commit', 'Commit, confirm and revert'],
  ['rollback', 'Roll back'],
  ['manage', 'Manage tokens, roles and settings'],
];
const SECTIONS = [
  ['firewall', 'Firewall: zones, rules, NAT'],
  ['network', 'Network: hostname, interfaces'],
  ['services', 'Services: DNS and DHCP'],
  ['vpn', 'VPN: tunnels and devices'],
];
const roleDraft = { name: '', can: { edit: true, commit: true }, limit: false, sections: {} };

function checks(list, picked, prefix) {
  return list.map(([key, label]) => {
    const id = prefix + key;
    return h('div', { class: 'check' },
      h('input', { type: 'checkbox', id, checked: !!picked[key], onchange: (e) => { picked[key] = e.target.checked; } }),
      h('label', { for: id }, label));
  });
}

function admin() {
  const s = state.status || {};
  const out = [h('div', { class: 'panel' },
    h('h2', null, 'You'),
    h('p', null, state.me ? state.me.name + ', role ' + state.me.role : ''),
    state.me && state.me.sections ? h('p', { class: 'dim' }, 'This role may make ' + held(state.me) + '.') : null)];
  const https = s.https;
  if (https) {
    out.push(h('div', { class: 'panel' },
      h('h2', null, 'Managing this box from another machine'),
      h('p', null, 'Save the box there with ', h('code', null, 'ox remote add <name> https://<this box>:' + https.listen.split(':').pop()),
        ' and an access token, then run ', h('code', null, 'ox --remote <name> status'), '.'),
      h('p', null, 'It shows the fingerprint of the certificate it was offered. It should be this one:'),
      h('p', { class: 'secret mono' }, https.fingerprint)));
  }
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
              state.roles.map((r) => h('option', { value: r.name, selected: r.name === tokenDraft.role }, r.name)))),
          field('Expires after days', 'days', tokenDraft, { inputmode: 'numeric', placeholder: 'never' })),
        h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Create token')))));
  }
  const makeRole = (e) => {
    e.preventDefault();
    const picked = (o) => Object.keys(o).filter((k) => o[k]);
    const body = { name: roleDraft.name, can: picked(roleDraft.can) };
    if (roleDraft.limit) body.sections = picked(roleDraft.sections);
    act(() => call('POST', '/v1/roles', body), (r) => { roleDraft.name = ''; return 'Role ' + r.name + ' made.'; });
  };
  out.push(h('div', { class: 'panel' },
    h('h2', null, 'Roles'),
    h('p', { class: 'dim' }, 'A role says what a token may do. Every role can read the config and status. A role held to parts of the config can only save, approve or commit changes that stay inside them.'),
    table(['Role', 'May', 'Where', ''],
      state.roles.map((r) => [r.name, r.can.join(', '), held(r) || 'any part of the config',
        r.builtin ? h('span', { class: 'dim' }, 'built in')
          : may('manage') ? h('button', { class: 'danger', onclick: () => act(() => call('DELETE', '/v1/roles/' + r.name), 'Deleted role ' + r.name + '.') }, 'Delete')
            : ''])),
    may('manage') ? h('form', { onsubmit: makeRole },
      h('h3', null, 'Make a role'),
      h('div', { class: 'fields' },
        field('Name', 'name', roleDraft, { required: true, pattern: '[a-z][a-z0-9-]*', placeholder: 'helpdesk' })),
      h('p', null, 'It may:'),
      checks(ACTIONS, roleDraft.can, 'can-'),
      h('div', { class: 'check' },
        h('input', { type: 'checkbox', id: 'role-limit', checked: roleDraft.limit, onchange: (e) => { roleDraft.limit = e.target.checked; render(); } }),
        h('label', { for: 'role-limit' }, 'Only in some parts of the config')),
      roleDraft.limit ? checks(SECTIONS, roleDraft.sections, 'sec-') : null,
      h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'Make role'))) : null));
  return out;
}

refresh(true);
setInterval(() => { if (state.token) refresh(false); }, 2000);

// Drives the web interface in a headless browser, as a person would: types,
// clicks, reads the page. It needs only Node 22 or later and Chrome, or
// Firefox with BROWSER=firefox.
//
//   node tests/web/drive.mjs <base-url> <setup-code> <out-dir>
//
// It expects a daemon with no config (start one with --dry-run and
// --listen-http), walks first-run setup and the simple screens, saves a
// picture of each step, and exits non-zero on the first thing that is wrong.
import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [base, code, out] = process.argv.slice(2);
if (!base || !code || !out) {
  console.error('usage: drive.mjs <base-url> <setup-code> <out-dir>');
  process.exit(2);
}
mkdirSync(out, { recursive: true });

// Two browsers, two remote-control protocols, one small interface:
// `evaluate(expression)` returns the JSON text of the expression's value,
// `capture()` a PNG as base64, `open(url)` loads a page.
const which = process.env.BROWSER || 'chrome';
const profile = mkdtempSync(join(tmpdir(), 'ox-web-'));
const extra = process.env.BROWSER_ARGS ? process.env.BROWSER_ARGS.split(' ') : [];
const errors = [];
const listening = (child, pattern) => new Promise((resolve, reject) => {
  let err = '';
  child.stderr.on('data', (d) => {
    err += d;
    const m = err.match(pattern);
    if (m) resolve(m[1]);
  });
  setTimeout(() => reject(new Error(which + ' did not start: ' + err.slice(-600))), 30000);
});
const socket = async (url) => {
  const ws = new WebSocket(url);
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve);
    ws.addEventListener('error', () => reject(new Error('cannot connect to ' + url)));
  });
  let next = 1;
  const waiting = new Map();
  const events = [];
  ws.addEventListener('message', (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && waiting.has(msg.id)) { waiting.get(msg.id)(msg); waiting.delete(msg.id); } else events.forEach((f) => f(msg));
  });
  return {
    send: (method, params = {}) => new Promise((resolve) => {
      const id = next++;
      waiting.set(id, resolve);
      ws.send(JSON.stringify({ id, method, params }));
    }),
    on: (f) => events.push(f),
  };
};

let browser;
let evaluate;
let capture;
let open;
if (which === 'firefox') {
  // WebDriver BiDi.
  browser = spawn(process.env.FIREFOX || 'firefox', ['--headless', '--remote-debugging-port=0', '--profile', profile,
    '--width=1280', '--height=900', ...extra, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
  const ws = await socket((await listening(browser, /WebDriver BiDi listening on (ws:\/\/\S+)/)) + '/session');
  const must = async (method, params) => {
    const r = await ws.send(method, params);
    if (r.type === 'error') throw new Error(method + ': ' + r.message);
    return r.result;
  };
  await must('session.new', { capabilities: {} });
  await must('session.subscribe', { events: ['log.entryAdded'] });
  ws.on((msg) => {
    if (msg.method === 'log.entryAdded' && msg.params.level === 'error') errors.push(msg.params.text);
  });
  const context = (await must('browsingContext.getTree', {})).contexts[0].context;
  open = (url) => must('browsingContext.navigate', { context, url, wait: 'complete' });
  evaluate = async (expression) => {
    const r = await must('script.evaluate', { expression, target: { context }, awaitPromise: true, resultOwnership: 'none' });
    if (r.type !== 'success') throw new Error(r.exceptionDetails?.text || 'script failed');
    return r.result.value;
  };
  capture = async () => (await must('browsingContext.captureScreenshot', { context, origin: 'document' })).data;
} else {
  // The Chrome DevTools Protocol.
  browser = spawn(process.env.CHROME || 'google-chrome', ['--headless=new', '--disable-gpu', '--no-first-run',
    '--remote-debugging-port=0', '--window-size=1280,900', '--user-data-dir=' + profile, ...extra, 'about:blank'],
  { stdio: ['ignore', 'ignore', 'pipe'] });
  const root = await listening(browser, /DevTools listening on (ws:\/\/\S+)/);
  const targets = await (await fetch(`http://127.0.0.1:${new URL(root).port}/json`)).json();
  const ws = await socket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
  ws.on((msg) => {
    if (msg.method === 'Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
    if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') errors.push(msg.params.args.map((a) => a.value).join(' '));
  });
  await ws.send('Page.enable');
  await ws.send('Runtime.enable');
  open = (url) => ws.send('Page.navigate', { url });
  evaluate = async (expression) => {
    const r = await ws.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || 'script failed');
    return r.result.result.value;
  };
  capture = async () => (await ws.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true })).result.data;
}
const quit = (status) => { browser.kill(); process.exit(status); };
// Every value crosses as JSON text, which both protocols carry the same way.
const js = async (expression) => JSON.parse(await evaluate(`Promise.resolve(${expression}).then((v) => JSON.stringify(v === undefined ? null : v))`));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const text = () => js('document.body.innerText');
let step = 0;
const shot = async (name) => {
  step += 1;
  writeFileSync(join(out, String(step).padStart(2, '0') + '-' + name + '.png'), Buffer.from(await capture(), 'base64'));
};
const fail = async (why) => {
  await shot('FAILED');
  console.error('FAILED: ' + why + '\n--- page ---\n' + (await text()).slice(0, 1500));
  quit(1);
};
// Waits until the page says something, as a person waits for it to appear.
const see = async (what, secs = 6) => {
  for (let i = 0; i < secs * 10; i += 1) {
    if ((await text()).includes(what)) return;
    await sleep(100);
  }
  await fail(`expected to see "${what}"`);
};
const notSee = async (what) => { if ((await text()).includes(what)) await fail(`did not expect "${what}"`); };
// Clicks the button, link or label whose text is exactly this.
const click = async (label, nth = 0) => {
  const ok = await js(`(() => {
    const all = [...document.querySelectorAll('button, label')].filter((e) => e.innerText.trim() === ${JSON.stringify(label)} && !e.disabled);
    if (!all[${nth}]) return false;
    all[${nth}].click();
    return true;
  })()`);
  if (!ok) await fail(`no button or label "${label}"`);
  await sleep(350);
};
const type = async (selector, value) => {
  const ok = await js(`(() => {
    const e = document.querySelector(${JSON.stringify(selector)});
    if (!e) return false;
    e.value = ${JSON.stringify(value)};
    e.dispatchEvent(new Event('input', { bubbles: true }));
    e.dispatchEvent(new Event('change', { bubbles: true }));
    return true;
  })()`);
  if (!ok) await fail(`no field ${selector}`);
};
// Clicks the control with this accessible name, as a screen reader user would.
const press = async (name) => {
  if (!(await js(`(() => { const e = document.querySelector('[aria-label=${JSON.stringify(name)}]'); if (!e) return false; e.click(); return true; })()`))) await fail('nothing is labelled "' + name + '"');
  await sleep(350);
};
// Turns an advanced feature's switch over.
const flip = async (id) => {
  if (!(await js(`(() => { const e = document.getElementById('adv-${id}'); if (!e) return false; e.click(); return true; })()`))) await fail('no switch for ' + id);
  await sleep(300);
};
const tabs = () => js(`[...document.querySelectorAll('nav button')].map((b) => b.innerText)`);

await open(base + '/');

// ── first-run setup ──
await see('Set up this box');
await see('Step 1 of 3');
await shot('setup-code');
await type('#f-code', 'AAAA-AAAA');
await click('Continue');
await see('that is not the setup code');
await type('#f-code', code.toLowerCase());
await click('Continue');
await see('Which port goes to the internet?');
await shot('setup-ports');
const ports = await js(`[...document.querySelectorAll('input[name=internet]')].map((e) => e.id.slice(4))`);
if (ports.length < 2) await fail('setup needs a machine with two ports, found ' + ports.join(','));
// The first port faces the internet, the second is the inside network.
await js(`document.getElementById('wan-${ports[0]}').click()`);
await sleep(300);
if (!(await js(`document.getElementById('lan-${ports[1]}').checked`))) await js(`document.getElementById('lan-${ports[1]}').click()`);
await sleep(300);
await type('#f-name', 'homebox');
await click('Review');
await see('This is what the box will do');
await see(`${ports[1]} is in zone lan`);
await see('You get 5 minutes');
await shot('setup-review');
await click('Apply safely');

// ── Home ──
await see('The box is set up');
await see('It undoes itself in');
if ((await tabs()).join(',') !== 'Home,Access,Settings') await fail('a new box shows only the three simple tabs, got ' + (await tabs()));
await shot('home-pending');
await click('Keep it');
await see('Kept. The change is now permanent.');
await see(process.env.OX_WEB_KERNEL === '1' ? 'The firewall is running' : 'Dry run');
await see('Inside network');
await see('Can reach: Internet');
await see('Save your access token now');
await see('Everything is blocked. Nothing is let in.');
await shot('home');

// "Is something blocked?" with no interface names.
await type('#f-from', '198.51.100.7');
await type('#f-to', '192.168.10.1');
await click('Check');
await see('Blocked');
await see('Nothing allows it, and anything not allowed is blocked.');
await shot('home-check');

// ── Access: block the inside network from the internet, review, apply ──
await click('Access');
await see('Who can reach what');
await see('Let in from the internet');
await shot('access');
await click('block');
await see('What will change');
await see('Inside network can no longer reach Internet');
await see('You get 2 minutes');
await shot('review');
await click('Apply safely');
await see('Applied. Check things still work');
await click('Keep it');
await see('Kept.');
await click('Access');
await see('allow');
await notSee('1 change waiting');

// A task from Access: let something in, then discard it at the review.
await click('Let something in');
await see('Forward a port');
await type('#f-name', 'Web server');
await type('#f-to', '192.168.10.20');
await shot('task-forward');
await click('Cancel');
await see('Who can reach what');

// ── Settings: advanced screens are opt-in ──
await click('Settings');
await see('Advanced features');
await see('Save your access token now');
await click('I have saved it');
await notSee('Save your access token now');
await shot('settings');
await flip('rules');
if (!(await tabs()).includes('Rules')) await fail('switching on the rule list adds its tab');
await click('Rules');
await see('lan → self');
await shot('advanced-rules');
await click('Settings');
await flip('rules');
if ((await tabs()).includes('Rules')) await fail('switching it off hides the tab again');
for (const id of ['nat', 'network', 'changes', 'explain', 'audit', 'admin']) await flip(id);
await sleep(300);
for (const tab of ['NAT', 'Network', 'Changes', 'Explain', 'Audit', 'Admin']) {
  await click(tab);
  await sleep(500);
  if (errors.length) await fail('the page reported an error on ' + tab + ': ' + errors.join(' | '));
}
await see('Access tokens');
await shot('advanced-admin');

// Back to the simple layer: the advanced tabs go away again, and Home is
// as a returning owner sees it.
for (const id of ['nat', 'network', 'changes', 'explain', 'audit', 'admin']) {
  await click('Settings');
  await flip(id);
}
if ((await tabs()).join(',') !== 'Home,Access,Settings') await fail('with every switch off, only the simple tabs remain, got ' + (await tabs()));
// Add a guest network in one step and see it in the grid, kept apart.
await click('Home');
await click('Add a network, such as one for guests');
await see('Add a network');
await type('#f-name', 'Guest Wi-Fi');
await type('#f-vlan', '20');
await shot('task-network');
await click('Review');
await see('A new network: Guest Wi-Fi');
await see('Guest Wi-Fi can reach Internet');
await shot('review-network');
await click('Apply safely');
await see('Applied. Check things still work');
await click('Keep it');
await see('Kept.');
await click('Access');
await see('Guest Wi-Fi');
if (!(await js(`[...document.querySelectorAll('tbody tr')].some((r) => r.innerText.startsWith('Guest Wi-Fi') && r.innerText.includes('Blocked') && r.innerText.includes('Allowed'))`))) {
  await fail('the guest network reaches the internet and is blocked from the inside network');
}
await shot('access-with-guest');

// Block a website by name, see it listed, and lift the block.
await click('Home');
await click('Block a device or a website');
await see('Block a device or a website');
await type('#f-address', 'https://www.example.com/page');
await click('Review');
await see('example.com is blocked for every device');
await click('Apply safely');
await see('Applied. Check things still work');
await click('Keep it');
await see('Kept.');
await click('Home');
await click('Block a device or a website');
await see('Blocked websites');
await shot('task-block');
await press('Unblock example.com');
await see('example.com is no longer blocked');
await click('Discard');
await see('Discarded. Nothing was changed.');

// Allow the inside network out again, the same way it was blocked.
await click('Access');
await press('Allow Inside network to Internet');
await see('Inside network can reach Internet');
await click('Apply safely');
await see('Applied. Check things still work');
await click('Keep it');
await see('Kept.');
await click('Access');
await see('Who can reach what');
if (!(await js(`!!document.querySelector('[aria-label="Block Inside network to Internet"]')`))) await fail('the inside network is allowed out again');
await shot('access-allowed');
await click('Home');
await see('Common tasks');
await see('Can reach: Internet');
await notSee('Save your access token now');
await shot('home-clean');

if (errors.length) await fail('the page reported errors: ' + errors.join(' | '));
console.log('ok (' + which + '): setup, Home, Access, Review, Settings and every advanced screen; ' + step + ' pictures in ' + out);
quit(0);

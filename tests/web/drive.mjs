// Drives the web interface in a headless Chrome, as a person would: types,
// clicks, reads the page. It needs only Node 22 or later and Chrome.
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

const chrome = spawn(process.env.CHROME || 'google-chrome', [
  '--headless=new', '--disable-gpu', '--no-first-run', '--remote-debugging-port=0',
  // Inside a user namespace Chrome cannot build its own sandbox.
  ...(process.env.CHROME_ARGS ? process.env.CHROME_ARGS.split(' ') : []),
  '--window-size=1280,900', '--user-data-dir=' + mkdtempSync(join(tmpdir(), 'ox-web-')), 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'] });
const wsUrl = await new Promise((resolve, reject) => {
  let err = '';
  chrome.stderr.on('data', (d) => {
    err += d;
    const m = err.match(/DevTools listening on (ws:\/\/\S+)/);
    if (m) resolve(m[1]);
  });
  setTimeout(() => reject(new Error('Chrome did not start: ' + err)), 15000);
});
const port = new URL(wsUrl).port;
const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
const ws = new WebSocket(targets.find((t) => t.type === 'page').webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let next = 1;
const waiting = new Map();
const errors = [];
ws.addEventListener('message', (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && waiting.has(msg.id)) { waiting.get(msg.id)(msg); waiting.delete(msg.id); }
  if (msg.method === 'Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text);
  if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') errors.push(msg.params.args.map((a) => a.value).join(' '));
});
const send = (method, params = {}) => new Promise((resolve) => {
  const id = next++;
  waiting.set(id, resolve);
  ws.send(JSON.stringify({ id, method, params }));
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const js = async (expression) => {
  const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || 'script failed');
  return r.result.result.value;
};
const text = () => js('document.body.innerText');
let step = 0;
const shot = async (name) => {
  const r = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  step += 1;
  writeFileSync(join(out, String(step).padStart(2, '0') + '-' + name + '.png'), Buffer.from(r.result.data, 'base64'));
};
const fail = async (why) => {
  await shot('FAILED');
  console.error('FAILED: ' + why + '\n--- page ---\n' + (await text()).slice(0, 1500));
  chrome.kill();
  process.exit(1);
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
// Turns an advanced feature's switch over.
const flip = async (id) => {
  if (!(await js(`(() => { const e = document.getElementById('adv-${id}'); if (!e) return false; e.click(); return true; })()`))) await fail('no switch for ' + id);
  await sleep(300);
};
const tabs = () => js(`[...document.querySelectorAll('nav button')].map((b) => b.innerText)`);

await send('Page.enable');
await send('Runtime.enable');
await send('Page.navigate', { url: base + '/' });

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
await see('Dry run');
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

if (errors.length) await fail('the page reported errors: ' + errors.join(' | '));
console.log('ok: setup, Home, Access, Review, Settings and every advanced screen; ' + step + ' pictures in ' + out);
chrome.kill();
process.exit(0);

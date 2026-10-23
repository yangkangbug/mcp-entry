// Dependency-free DOM/state tests. Not browser isolation or visual QA.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../../internal/gateway/binding_assets');
const src = fs.readFileSync(path.join(root, 'binding.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
class Element {
  constructor() { this.handlers = {}; this.value = ''; this.textContent = ''; this.disabled = false; this.checked = false; this.hidden = false; }
  addEventListener(name, fn) { this.handlers[name] = fn; }
  fire(name) { return this.handlers[name]?.({preventDefault() {}}); }
}
function setup({hash = '#' + 'a'.repeat(43) + '.' + 'b'.repeat(43), search = '', historyFails = false, origin = 'http://127.0.0.1:8080'} = {}) {
  const elements = {};
  for (const m of html.matchAll(/<\w+[^>]*\bid="([^"]+)"[^>]*>/g)) {
    const el = elements[m[1]] = new Element(); el.disabled = m[0].includes('disabled'); el.hidden = m[0].includes('hidden');
  }
  const translated = [...html.matchAll(/data-i18n="([^"]+)"[^>]*>([^<]*)</g)].map(m => Object.assign(new Element(), {dataset: {i18n: m[1]}, textContent: m[2]}));
  const document = {getElementById: id => elements[id], querySelectorAll: () => translated, documentElement: {}};
  const calls = [], pending = [], history = [];
  const window = {location: {hash, search, pathname: '/binding/', origin, protocol: new URL(origin).protocol, hostname: new URL(origin).hostname}, handlers: {}, addEventListener(name, fn) { this.handlers[name] = fn; }};
  window.history = {replaceState(...args) { if (historyFails) throw Error('blocked'); history.push(args); window.location.hash = ''; window.location.search = ''; }};
  vm.runInNewContext(src, {document, window, AbortController, fetch(url, opts) { calls.push({url, opts}); return new Promise((resolve, reject) => pending.push({resolve, reject})); }});
  return {e: elements, calls, pending, window, history};
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const details = {state: 'pending', service_id: 'crm', identity: {tenant: 'test', principal: 'alice'}, auth_type: 'bearer', expires_at: '2099-01-01T00:00:00Z'};
async function respond(h, body, status = 200) { h.pending.shift().resolve({ok: status === 200, status, json: async () => body}); await tick(); }
function verify(h) { h.e.entry.value = 'independent-entry'; return h.e['identity-form'].fire('submit'); }
async function verified(h) { verify(h); await respond(h, details); }
function save(h) { h.e.credential.value = 'provider-secret'; h.e.confirm.checked = true; return h.e['binding-form'].fire('submit'); }
(async () => {
  let h = setup();
  assert.equal(h.calls.length, 0, 'no automatic inspection or submission');
  assert.equal(h.window.location.hash, '');
  assert.deepEqual(h.history[0], [null, '', '/binding/']);
  assert.equal(h.e.details.hidden, true);
  assert.equal(h.e.credential.disabled, true);
  verify(h);
  assert.equal(h.calls.length, 1);
  assert.equal(h.e.entry.value, '');
  assert.equal(h.calls[0].opts.headers.Authorization, 'Bearer independent-entry');
  assert.equal(h.calls[0].opts.credentials, 'omit');
  assert.equal(h.calls[0].opts.redirect, 'error');
  assert.equal(h.calls[0].opts.cache, 'no-store');
  assert.equal(h.calls[0].opts.referrerPolicy, 'no-referrer');
  assert.deepEqual(JSON.parse(h.calls[0].opts.body), {session_locator: 'a'.repeat(43), capability: 'b'.repeat(43)});
  h.e['identity-form'].fire('submit'); assert.equal(h.calls.length, 1, 'double verify blocked');
  await respond(h, {...details, service_id: '<img src=x onerror=alert(1)>'});
  assert.equal(h.e.service.textContent, '<img src=x onerror=alert(1)>', 'untrusted text uses textContent');
  assert.equal(h.e.gateway.textContent, 'http://127.0.0.1:8080');
  assert.equal(h.e.details.hidden, false);
  h.e.credential.value = 'provider-secret';
  h.e['binding-form'].fire('submit'); assert.equal(h.calls.length, 1, 'explicit consent required');
  save(h);
  assert.equal(h.e.credential.value, '');
  assert.deepEqual(JSON.parse(h.calls[1].opts.body), {session_locator: 'a'.repeat(43), capability: 'b'.repeat(43), credential: 'provider-secret', confirm: true});
  h.e['binding-form'].fire('submit'); assert.equal(h.calls.length, 2, 'double save blocked');
  await respond(h, {binding_saved: true, discovery_status: 'not_observed'});
  assert.match(h.e.message.textContent, /凭据已保存/);
  assert.match(h.e.message.textContent, /不代表工具已发现/);
  assert.equal(h.e.details.hidden, true); assert.equal(h.e.identity.textContent, '');
  h.e.language.value = 'en'; h.e.language.fire('change'); assert.match(h.e.message.textContent, /Credential saved/);
  h.e['binding-form'].fire('submit'); assert.equal(h.calls.length, 2);

  // Transport admission is fail-closed before either form can send a secret.
  for (const origin of ['http://127.0.0.2:8080', 'http://127.2.3.4:8080', 'http://gateway.example:8443', 'http://localhost:8080', 'http://127.0.0.1.example:8080', 'http://192.0.2.1', 'http://[::ffff:7f00:1]', 'file:///binding/']) {
    h = setup({origin});
    assert.equal(h.window.location.hash, '', 'strip capability even on unsafe transport');
    assert.equal(h.e.entry.disabled, true);
    assert.match(h.e.message.textContent, /不安全的页面地址/);
    verify(h); save(h); assert.equal(h.calls.length, 0);
    h.e.language.value = 'en'; h.e.language.fire('change');
    assert.match(h.e.message.textContent, /Unsafe page address/);
  }
  for (const origin of ['https://gateway.example:8443', 'https://192.0.2.1:8443', 'http://127.0.0.1:8080', 'http://[::1]:8080']) {
    h = setup({origin});
    assert.equal(h.calls.length, 0, 'HTTPS and loopback never auto-submit');
    assert.equal(h.window.location.hash, '');
    await verified(h);
    assert.equal(h.e.gateway.textContent, origin);
    assert.equal(h.calls[0].url, '/binding/api/session/inspect');
    save(h);
    assert.equal(h.calls[1].url, '/binding/api/session/confirm');
    await respond(h, {binding_saved: true, discovery_status: 'ready'});
    assert.match(h.e.message.textContent, /凭据已保存/);
    assert.equal(h.calls.length, 2);
  }

  for (const options of [{hash: ''}, {hash: '#bad'}, {search: '?secret=bad'}, {historyFails: true}]) {
    h = setup(options); verify(h); save(h); assert.equal(h.calls.length, 0, 'invalid URL fails closed'); assert.equal(h.e.entry.disabled, true);
  }
  for (const event of ['offline', 'pagehide']) {
    h = setup(); verify(h); h.window.handlers[event]();
    assert.equal(h.calls[0].opts.signal.aborted, true);
    await respond(h, details);
    assert.equal(h.e.details.hidden, true); assert.equal(h.e.service.textContent, '');
    assert.equal(h.e.entry.value, ''); assert.equal(h.e.credential.value, '');
    h.e['identity-form'].fire('submit'); assert.equal(h.calls.length, 1, 'late response cannot revive page');
    h = setup(); await verified(h); save(h); h.window.handlers[event]();
    await respond(h, {binding_saved: true});
    assert.match(h.e.message.textContent, /保存结果未知/); assert.equal(h.e.details.hidden, true);
  }
  h = setup(); await verified(h); h.e.credential.value = 'secret'; h.e.close.fire('click');
  assert.equal(h.e.credential.value, ''); assert.equal(h.calls.length, 1, 'local clear never submits');
  for (const status of [401, 403, 409, 410, 503]) {
    h = setup(); verify(h); await respond(h, {error: 'untrusted secret error'}, status);
    assert.equal(h.e.credential.disabled, true); assert.doesNotMatch(h.e.message.textContent, /untrusted/);
  }
  for (const body of [{}, {...details, expires_at: '2000-01-01'}, {...details, identity: null}]) {
    h = setup(); verify(h); await respond(h, body); assert.equal(h.e.details.hidden, true);
  }
  h = setup(); await verified(h); save(h); h.pending.shift().reject(Error('network provider-secret')); await tick();
  assert.match(h.e.message.textContent, /保存结果未知/); assert.doesNotMatch(h.e.message.textContent, /provider-secret/);
  assert.equal(h.e.credential.value, ''); h.e['binding-form'].fire('submit'); assert.equal(h.calls.length, 2);
  h = setup(); await verified(h); save(h); await respond(h, {}); assert.match(h.e.message.textContent, /保存结果未知/);
  // A response can arrive before its JSON body. Neither stage may revive a dismissed page.
  for (const event of ['offline', 'pagehide', 'close']) {
    h = setup(); verify(h);
    let finishJSON;
    h.pending.shift().resolve({ok: true, status: 200, json: () => new Promise(resolve => { finishJSON = resolve; })});
    await tick();
    if (event === 'close') h.e.close.fire('click'); else h.window.handlers[event]();
    finishJSON(details); await tick();
    assert.equal(h.e.details.hidden, true); assert.equal(h.e.service.textContent, '');
  }
  h = setup(); await verified(h); save(h);
  let finishSaveJSON;
  h.pending.shift().resolve({ok: true, status: 200, json: () => new Promise(resolve => { finishSaveJSON = resolve; })});
  await tick(); h.e.close.fire('click'); finishSaveJSON({binding_saved: true}); await tick();
  assert.match(h.e.message.textContent, /保存结果未知/); assert.equal(h.e.details.hidden, true);
  h = setup(); await verified(h); save(h);
  h.pending.shift().resolve({ok: true, status: 200, json: async () => { throw Error('not JSON'); }}); await tick();
  assert.match(h.e.message.textContent, /保存结果未知/); assert.equal(h.calls.length, 2);
  for (const status of ['ready', 'unavailable', 'not_completed']) {
    h = setup(); await verified(h); save(h); await respond(h, {binding_saved: true, discovery_status: status});
    assert.match(h.e.message.textContent, /凭据已保存/); assert.equal(h.e.save.disabled, true);
  }
  h = setup(); await verified(h); h.e.credential.value = 'never-send'; h.e.cancel.fire('click');
  assert.equal(h.e.credential.value, ''); assert.equal(h.e.details.hidden, true);
  assert.equal(h.calls[1].url, '/binding/api/session/cancel');
  assert.equal(JSON.parse(h.calls[1].opts.body).credential, undefined);
  h.e.cancel.fire('click'); assert.equal(h.calls.length, 2);
  await respond(h, {state: 'canceled'}); assert.match(h.e.message.textContent, /链接已取消/);
  h = setup(); await verified(h); h.e.cancel.fire('click'); h.pending.shift().reject(Error('lost')); await tick();
  assert.match(h.e.message.textContent, /取消结果未确认/); assert.equal(h.calls.length, 2);
  assert.doesNotMatch(src, /localStorage|sessionStorage|document\.cookie|innerHTML|setInterval/);
  assert.doesNotMatch(html, /https?:\/\//);
  for (const id of ['entry', 'credential']) assert.match(html, new RegExp('id="' + id + '" type="password" autocomplete="off"'));
  console.log('client-binding frontend state/DOM tests passed (not browser QA)');
})().catch(error => { console.error(error); process.exitCode = 1; });

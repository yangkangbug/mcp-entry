(() => {
  'use strict';
  let bearer = '';
  let bindings = [];
  let busy = false;
  let epoch = 0;
  let pending = null;
  let language = 'zh-CN';
  let identity = null;
  let currentMessage = {key: 'notConnected', values: {}};
  const translations = {
    'zh-CN': {
      title: '连接你的账号 · MCP Entry', label: 'MCP ENTRY · 本地测试', language: '语言 / Language',
      heading: '已连接的账号',
      intro: '此页面用于首次连接或恢复访问，日常使用 MCP 时无需保持打开。当前本地原型仅用于虚构凭据测试。',
      authenticate: '1. 验证入口身份',
      entryHelp: '输入预先配置的入口凭据。凭据仅保留在当前页面内存中，关闭页面或断开连接后会清除。',
      entryLabel: '入口凭据', connect: '连接', disconnect: '断开连接', manage: '2. 管理本人绑定',
      refresh: '刷新状态', system: '系统', credentialLabel: '新的下游凭据', expiryLabel: '到期时间（本地时间，可选）',
      providerHelp: '请另行向下游服务获取新凭据。本页面不会签发凭据或自动刷新下游授权。',
      replace: '保存新凭据', revoke: '撤销所选绑定', notConnected: '尚未连接。',
      signedIn: '当前身份：{principal}（{tenant}）', expires: '到期时间：{date}',
      active: '已绑定', unbound: '未绑定', revoked: '已撤销', expired: '已过期', unknownState: '状态未知',
      hintStored: '凭据已保存，但不代表当前仍可访问下游服务。',
      hintUnbound: '保存下游凭据后即可连接。', hintExpired: '已达到本地到期时间。请获取新的下游凭据并保存替换。',
      loaded: '状态已加载。页面不会返回凭据明文。',
      disconnected: '已断开连接并清除页面凭据。已提交的变更仍可能完成；请重新连接后核对。',
      unexpected: '响应格式异常。再次尝试变更前，请先刷新状态。',
      error401: '入口认证被拒绝或已过期。请使用有效入口凭据重新连接。',
      error403: '请求被拒绝。请检查页面地址和访问权限。',
      error409: '绑定已发生变化。再次操作前，请先刷新状态。',
      error400: '请求无效。请检查凭据和到期时间。',
      error503: '状态暂不可用。再次操作前请先刷新，不要直接认定变更失败。',
      requestFailed: '请求失败。再次尝试变更前，请先刷新状态。',
      interrupted: '连接中断。再次尝试变更前，请先刷新状态。',
      futureExpiry: '请选择未来的到期时间。', saved: '新凭据已保存。', bindingRevoked: '绑定已撤销。', providerHint: '{hint}',
      confirmRevoke: '确定撤销你在 {system} 的绑定吗？',
      savedDiscovered: '新凭据已保存，工具发现已完成。可用工具仍受你的权限策略约束。',
      savedUnavailable: '新凭据已保存，但下游工具发现暂不可用。再次替换前，请先检查状态及下游访问情况。',
      savedAuthentication: '新凭据已保存，但下游拒绝了认证。请核对凭据，必要时重新绑定；这不能证明凭据已过期或被撤销。',
      savedPermission: '新凭据已保存，但下游拒绝了访问权限。请检查下游权限；这不代表凭据已过期。',
      savedUnfinished: '新凭据已保存，但工具发现尚未完成。再次尝试前，请先检查状态。'
    },
    en: {
      title: 'Connect your accounts · MCP Entry', label: 'MCP ENTRY · LOCAL TEST', language: 'Language / 语言',
      heading: 'Your connected accounts',
      intro: 'Use this page for first connection or recovery. Normal MCP use does not require keeping it open. This local prototype is for synthetic credentials only.',
      authenticate: '1. Authenticate',
      entryHelp: "Enter your preprovisioned entry credential. It stays in this page's memory only. Closing or disconnecting the page clears it.",
      entryLabel: 'Entry credential', connect: 'Connect', disconnect: 'Disconnect', manage: '2. Manage your binding',
      refresh: 'Refresh status', system: 'System', credentialLabel: 'Replacement downstream credential', expiryLabel: 'Expires at (your local time, optional)',
      providerHelp: 'Acquire a replacement from the downstream provider separately. This page does not issue or automatically refresh provider grants.',
      replace: 'Save replacement', revoke: 'Revoke selected binding', notConnected: 'Not connected.',
      signedIn: 'Signed in as {principal} ({tenant})', expires: 'expires {date}',
      active: 'Active', unbound: 'Unbound', revoked: 'Revoked', expired: 'Expired', unknownState: 'Unknown state',
      hintStored: 'Credential stored. This does not prove current provider access.',
      hintUnbound: 'Save a provider credential to connect.', hintExpired: 'Local expiry reached. Obtain a fresh provider credential and save a replacement.',
      loaded: 'Status loaded. Credentials are never returned.',
      disconnected: 'Disconnected. Page credentials cleared. An already-submitted change may have completed; reconnect to check.',
      unexpected: 'Unexpected response. Refresh status before retrying a change.',
      error401: 'Entry authentication rejected or expired. Connect again with a valid entry credential.',
      error403: 'Request denied. Check the page address and your permissions.',
      error409: 'Binding changed. Refresh status before trying again.',
      error400: 'Invalid request. Check the credential and expiry.',
      error503: 'State unavailable. Refresh status before retrying; do not assume the change failed.',
      requestFailed: 'Request failed. Refresh status before retrying.',
      interrupted: 'Connection interrupted. Refresh status before retrying a change.',
      futureExpiry: 'Choose a future expiry.', saved: 'Replacement saved.', bindingRevoked: 'Binding revoked.', providerHint: '{hint}',
      confirmRevoke: 'Revoke your {system} binding?',
      savedDiscovered: 'Replacement saved. Discovery completed; tools remain subject to your policy.',
      savedUnavailable: 'Replacement saved, but downstream discovery is unavailable. Check status and provider access before replacing again.',
      savedAuthentication: 'Replacement saved, but the provider rejected authentication. Check the credential and rebind if needed; this does not prove expiry or revocation.',
      savedPermission: 'Replacement saved, but the provider denied permission. Check provider permissions; this does not mean the credential expired.',
      savedUnfinished: 'Replacement saved; discovery did not finish. Check status before retrying.'
    }
  };
  const hintKeys = new Map([
    ['Credential stored. This does not prove current provider access.', 'hintStored'],
    ['Save a provider credential to connect.', 'hintUnbound'],
    ['Local expiry reached. Obtain a fresh provider credential and save a replacement.', 'hintExpired'],
    ['Binding revoked.', 'bindingRevoked'], ['Replacement saved.', 'saved'],
    [translations.en.savedDiscovered, 'savedDiscovered'], [translations.en.savedUnavailable, 'savedUnavailable'],
    [translations.en.savedAuthentication, 'savedAuthentication'], [translations.en.savedPermission, 'savedPermission'],
    [translations.en.savedUnfinished, 'savedUnfinished']
  ]);
  const $ = id => document.getElementById(id);
  const text = (key, values = {}) => translations[language][key].replace(/\{(\w+)\}/g, (_, name) => String(values[name] ?? ''));
  const message = (key, values = {}) => {
    currentMessage = {key, values};
    $('message').textContent = text(key, values);
  };
  class PageError extends Error {
    constructor(key) { super(key); this.key = key; }
  }
  function applyLanguage() {
    document.documentElement.lang = language;
    document.title = text('title');
    for (const element of document.querySelectorAll('[data-i18n]')) {
      element.textContent = text(element.dataset.i18n);
    }
    if (identity) render({bindings, ...identity});
    message(currentMessage.key, currentMessage.values);
  }
  const reset = () => {
    epoch++;
    if (pending) pending.abort();
    pending = null;
    bearer = '';
    bindings = [];
    identity = null;
    busy = false;
    $('entry').value = '';
    $('credential').value = '';
    $('expiry').value = '';
    $('identity').textContent = '';
    $('bindings').replaceChildren();
    $('system').replaceChildren();
    controls();
  };
  const controls = () => {
    $('entry').disabled = busy;
    $('login-form').querySelector('button[type="submit"]').disabled = busy;
    $('refresh').disabled = !bearer || busy;
    for (const id of ['system', 'credential', 'expiry', 'replace', 'revoke']) {
      $(id).disabled = !bearer || busy || bindings.length === 0;
    }
  };
  async function request(path, body, signal) {
    const headers = {Authorization: 'Bearer ' + bearer, Accept: 'application/json'};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal});
    let data;
    try { data = await response.json(); }
    catch { throw new PageError('unexpected'); }
    if (!response.ok) {
      const errors = {401: 'error401', 403: 'error403', 409: 'error409', 400: 'error400', 503: 'error503'};
      throw new PageError(errors[response.status] || 'requestFailed');
    }
    return data;
  }
  function render(data) {
    bindings = data.bindings;
    identity = {principal: data.principal, tenant: data.tenant};
    $('identity').textContent = text('signedIn', identity);
    const previous = $('system').value;
    $('bindings').replaceChildren();
    $('system').replaceChildren();
    for (const binding of bindings) {
      const item = document.createElement('li');
      const state = ['active', 'unbound', 'revoked', 'expired'].includes(binding.state) ? binding.state : 'unknownState';
      const hint = hintKeys.get(binding.hint);
      const hintText = hint ? text(hint) : binding.hint;
      item.textContent = binding.system + ': ' + text(state) + (binding.expires_at ? ' · ' + text('expires', {date: new Date(binding.expires_at).toLocaleString(language)}) : '') + (hintText ? ' · ' + hintText : '');
      $('bindings').append(item);
      const option = document.createElement('option');
      option.value = binding.system;
      option.textContent = binding.system;
      $('system').append(option);
    }
    if (bindings.some(binding => binding.system === previous)) $('system').value = previous;
  }
  async function perform(action) {
    if (busy) return;
    busy = true;
    controls();
    const current = epoch;
    pending = new AbortController();
    const signal = pending.signal;
    try { await action(signal, current); }
    catch (error) { if (current === epoch && error.name !== 'AbortError') message(error instanceof PageError ? error.key : error instanceof TypeError ? 'interrupted' : 'requestFailed'); }
    finally { if (current === epoch) { busy = false; pending = null; controls(); } }
  }
  async function refresh(signal, current) {
    const data = await request('/account/api/bindings', undefined, signal);
    if (current !== epoch) return;
    render(data);
    message('loaded');
  }
  $('login-form').addEventListener('submit', event => {
    event.preventDefault();
    if (busy) return;
    const token = $('entry').value;
    reset();
    bearer = token;
    perform(refresh);
  });
  $('refresh').addEventListener('click', () => perform(refresh));
  $('disconnect').addEventListener('click', () => { reset(); message('disconnected'); });
  $('binding-form').addEventListener('submit', event => {
    event.preventDefault();
    if (busy) return;
    const binding = bindings.find(item => item.system === $('system').value);
    if (!binding) return;
    const body = {expected_generation: binding.generation, credential: $('credential').value};
    if ($('expiry').value) {
      const date = new Date($('expiry').value);
      if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) { message('futureExpiry'); return; }
      body.expires_at = date.toISOString();
    }
    $('credential').value = '';
    perform(async (signal, current) => {
      const result = await request('/account/api/bindings/' + encodeURIComponent(binding.system), body, signal);
      body.credential = '';
      if (current !== epoch) return;
      await refresh(signal, current);
      if (current === epoch) message(hintKeys.get(result.hint) || (result.hint ? 'providerHint' : 'saved'), {hint: result.hint});
    }).finally(() => { body.credential = ''; });
  });
  $('revoke').addEventListener('click', () => {
    if (busy) return;
    const binding = bindings.find(item => item.system === $('system').value);
    if (!binding || !window.confirm(text('confirmRevoke', {system: binding.system}))) return;
    perform(async (signal, current) => {
      await request('/account/api/bindings/' + encodeURIComponent(binding.system) + '/revoke', {expected_generation: binding.generation}, signal);
      if (current !== epoch) return;
      await refresh(signal, current);
      if (current === epoch) message('bindingRevoked');
    });
  });
  $('language').addEventListener('change', () => {
    const selected = $('language').value;
    if (selected !== 'zh-CN' && selected !== 'en') return;
    language = selected;
    applyLanguage();
  });
  window.addEventListener('pagehide', reset);
  applyLanguage();
})();

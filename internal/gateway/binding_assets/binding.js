(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  let language = 'zh-CN';
  const zh = {};
  document.querySelectorAll('[data-i18n]').forEach(el => { zh[el.dataset.i18n] = el.textContent; });
  Object.assign(zh, {
    canceling: '正在取消链接；页面秘密已清除。', canceled: '链接已取消，页面秘密已清除。', cancelUnknown: '取消结果未确认；页面秘密已清除，但服务器链接可能仍有效直到到期。请查询状态，不要假定已取消。',
    savedReady: '凭据已保存，工具发现已完成；工具仍受权限策略约束。不保证未来服务可用，也未执行或重放任何业务请求。',
    savedUnavailable: '凭据已保存，但工具发现不可用。请先查询状态、核对服务凭据和权限；不要把发现失败当成保存失败，也不要直接重试保存。未执行任何业务请求。',
    savedIncomplete: '凭据已保存，但工具发现未完成。请先查询连接状态；不要直接重试保存。未执行任何业务请求。',
    title: '一次连接 · MCP Entry', ready: '请独立验证本人身份。尚未提交任何凭据。',
    invalid: '链接无效或缺失。请让 Agent 生成新的链接；不要把凭据发给 Agent。',
    verifying: '正在验证本人身份和连接目标…', verified: '身份和目标已验证。请核对上方信息后，再输入服务凭据并明确确认。',
    saving: '正在提交一次保存；请勿重复操作。',
    saved: '凭据已保存，但不代表工具已发现或服务可用，也未执行任何业务请求。请让 Agent 查询连接状态，再由你决定后续操作。',
    rejected: '身份认证失败或访问被拒绝。页面秘密已清除。请独立检查当前本人网关 token 和权限，再生成新链接。',
    conflict: '链接或访问权限不可用：链接可能已失效、到期、使用过，或绑定状态已变化。页面秘密已清除；请先查询连接状态，再决定是否生成新链接。',
    failed: '验证失败或返回异常。页面秘密已清除，请检查连接状态后生成新链接。',
    unknown: '保存结果未知：请求可能已完成。页面秘密已清除，不会重试。请让 Agent 查询连接状态；不要直接再次提交，也不要自动重放原业务请求。',
    cleared: '页面秘密已清除。此页面不能继续；服务器链接不一定已撤销。需要时请生成新链接。',
    consentNeeded: '请先核对目标、填写服务凭据，并勾选明确确认。'
  });
  const en = {
    cancel: 'Cancel this link', canceling: 'Canceling link; page secrets cleared.', canceled: 'Link canceled. Page secrets cleared.', cancelUnknown: 'Cancellation unconfirmed. Page secrets cleared, but the server link may remain valid until expiry. Check status; do not assume cancellation.',
    savedReady: 'Credential saved and tool discovery completed; tools remain subject to policy. Future availability is not guaranteed. No business operation ran or was replayed.',
    savedUnavailable: 'Credential saved, but tool discovery is unavailable. Check status, provider credentials and permissions. Discovery failure is not save failure; do not blindly repeat the save. No business operation ran.',
    savedIncomplete: 'Credential saved, but discovery did not complete. Check connection status; do not blindly repeat the save. No business operation ran.',
    title: 'One-time connection · MCP Entry', heading: 'Authorize one connection',
    intro: 'Local synthetic testing only. This page accepts provider credentials; it is not automatic third-party OAuth authorization and executes no business operation.',
    trust: 'Independently verify that the browser address is your trusted local gateway first. The link does not prove your identity. Never paste credentials into chat or ask an AI agent to fill them in.',
    step1: '1. Independently verify your identity', entryHelp: 'Enter your own current MCP gateway token, not an administrator token. The service and identity appear only after verification.',
    entryLabel: 'Your MCP gateway token', verify: 'Verify identity and target', step2: '2. Review target and explicitly confirm',
    gateway: 'Gateway', identity: 'Your identity (tenant / principal)', service: 'Service', auth: 'Credential type', expiry: 'Link expires at',
    providerHelp: 'Obtain synthetic test credentials from this service independently. Existing secrets are never returned. Saving may replace your existing binding for this service; it does not expand tool permissions.',
    credentialLabel: 'New provider credential', consent: 'I have checked the gateway, my identity and service, and authorize saving this credential.', save: 'Confirm and save once', close: 'Clear and end this page',
    privacy: 'Secrets remain only in page memory and password fields; leaving the page or going offline clears them. No browser storage, automatic retry or business request replay. Clearing this page does not revoke the server link; it may remain valid until expiry.',
    ready: 'Verify your identity independently. No credentials have been submitted.', invalid: 'Invalid or missing link. Ask the agent for a new link; never send it credentials.',
    verifying: 'Verifying identity and connection target…', verified: 'Identity and target verified. Review the information above before entering provider credentials and explicitly confirming.',
    saving: 'Submitting one save. Do not repeat this operation.',
    saved: 'Credential saved. This does not mean tools were discovered or the service is available. No business request ran. Ask the agent to check connection status, then decide what to do next.',
    rejected: 'Authentication or access rejected. Page secrets cleared. Independently check your current gateway token and permissions, then request a new link.',
    conflict: 'Link or access unavailable: the link may be invalid, expired, already used, or the binding changed. Page secrets cleared. Check connection status before deciding whether to request a new link.',
    failed: 'Verification failed or response invalid. Page secrets cleared. Check connection status and request a new link.',
    unknown: 'Save outcome unknown: the request may have completed. Page secrets cleared; no retry will occur. Ask the agent to check connection status. Do not resubmit blindly or automatically replay the original business request.',
    cleared: 'Page secrets cleared. This page cannot continue; the server link may not be revoked. Request a new link if needed.',
    consentNeeded: 'Review the target, enter a provider credential, and check explicit confirmation.'
  };
  let messageKey = 'ready';
  const renderMessage = key => { messageKey = key; $('message').textContent = (language === 'en' ? en : zh)[key]; };
  $('language').addEventListener('change', () => {
    language = $('language').value === 'en' ? 'en' : 'zh-CN';
    const words = language === 'en' ? en : zh;
    document.documentElement.lang = language;
    document.title = words.title;
    document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = words[el.dataset.i18n]; });
    renderMessage(messageKey);
  });

  // The URL capability is held only in this closure, never persisted. Strip it
  // before any request, even when malformed. A reload intentionally cannot resume.
  let locator = '', capability = '', bearer = '';
  let state = 'entry', epoch = 0, pending = null;
  const hadQuery = !!window.location.search;
  let fragment = window.location.hash.slice(1);
  try { window.history.replaceState(null, '', window.location.pathname); }
  catch (_) { fragment = ''; }
  let match = /^([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})$/.exec(fragment);
  if (match) { locator = match[1]; capability = match[2]; }
  const validLink = !!match;
  match = null;
  fragment = '';

  function clear(key) {
    // Abort is best-effort: it does not roll back a server commit. Incrementing
    // the epoch prevents a late response from restoring identity or secret UI.
    epoch++;
    if (pending) pending.abort();
    pending = null;
    locator = capability = bearer = '';
    $('entry').value = $('credential').value = '';
    $('confirm').checked = false;
    for (const id of ['entry', 'verify', 'credential', 'confirm', 'save', 'cancel']) $(id).disabled = true;
    for (const id of ['gateway', 'identity', 'service', 'auth', 'expiry']) $(id).textContent = '';
    $('details').hidden = true;
    state = 'ended';
    renderMessage(key);
  }
  function endPage() { clear(state === 'saving' ? 'unknown' : 'cleared'); }
  $('close').addEventListener('click', endPage);
  window.addEventListener('pagehide', endPage);
  window.addEventListener('offline', endPage);
  if (!validLink || hadQuery) { clear('invalid'); return; }
  renderMessage('ready');

  async function request(action, extra) {
    pending = new AbortController();
    return fetch('/binding/api/session/' + action, {
      method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      headers: {'Content-Type': 'application/json', Authorization: 'Bearer ' + bearer},
      body: JSON.stringify({session_locator: locator, capability, ...extra}), signal: pending.signal
    });
  }
  $('identity-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (state !== 'entry' || !$('entry').value) return;
    bearer = $('entry').value;
    $('entry').value = '';
    $('entry').disabled = $('verify').disabled = true;
    state = 'verifying';
    const current = ++epoch;
    renderMessage('verifying');
    try {
      const response = await request('inspect', {});
      if (current !== epoch) return;
      if (!response.ok) { clear(response.status === 401 ? 'rejected' : response.status === 403 || response.status === 409 || response.status === 410 ? 'conflict' : 'failed'); return; }
      const info = await response.json();
      if (current !== epoch) return;
      if (info.state !== 'pending' || typeof info.service_id !== 'string' || !info.service_id ||
          typeof info.identity?.tenant !== 'string' || typeof info.identity?.principal !== 'string' ||
          typeof info.auth_type !== 'string' || typeof info.expires_at !== 'string' ||
          !Number.isFinite(Date.parse(info.expires_at)) || Date.parse(info.expires_at) <= Date.now()) {
        clear('failed'); return;
      }
      pending = null;
      $('gateway').textContent = window.location.origin;
      $('identity').textContent = info.identity.tenant + ' / ' + info.identity.principal;
      $('service').textContent = info.service_id;
      $('auth').textContent = info.auth_type;
      $('expiry').textContent = info.expires_at;
      $('details').hidden = false;
      for (const id of ['credential', 'confirm', 'save', 'cancel']) $(id).disabled = false;
      state = 'verified';
      renderMessage('verified');
    } catch (_) { if (current === epoch) clear('failed'); }
  });
  $('cancel').addEventListener('click', async () => {
    if (state !== 'verified') return;
    // Explicit cancellation is separate from local dismissal. Clear local secrets
    // immediately; a failed/lost cancellation response never proves revocation.
    const result = request('cancel', {});
    pending = null;
    clear('canceling');
    const current = epoch;
    try {
      const response = await result;
      if (current !== epoch) return;
      const body = response.ok ? await response.json() : null;
      if (current !== epoch) return;
      renderMessage(body?.state === 'canceled' ? 'canceled' : 'cancelUnknown');
    } catch (_) { if (current === epoch) renderMessage('cancelUnknown'); }
  });
  $('binding-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (state !== 'verified') return;
    if (!$('confirm').checked || !$('credential').value) { renderMessage('consentNeeded'); return; }
    state = 'saving';
    const current = ++epoch;
    for (const id of ['credential', 'confirm', 'save', 'cancel']) $(id).disabled = true;
    renderMessage('saving');
    try {
      // Clear the input immediately after building the only request. No retry
      // path retains the provider credential, including malformed/lost responses.
      const result = request('confirm', {credential: $('credential').value, confirm: true});
      $('credential').value = '';
      const response = await result;
      if (current !== epoch) return;
      if (!response.ok) { clear(response.status === 401 ? 'rejected' : response.status === 403 || response.status === 409 || response.status === 410 ? 'conflict' : 'unknown'); return; }
      const resultBody = await response.json();
      if (current !== epoch) return;
      const savedMessage = {ready: 'savedReady', unavailable: 'savedUnavailable', not_completed: 'savedIncomplete'}[resultBody.discovery_status] || 'saved';
      clear(resultBody.binding_saved === true ? savedMessage : 'unknown');
    } catch (_) { if (current === epoch) clear('unknown'); }
  });
})();

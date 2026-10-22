(() => {
  'use strict';
  let bearer = '';
  let bindings = [];
  let busy = false;
  let epoch = 0;
  let pending = null;
  const $ = id => document.getElementById(id);
  const message = text => { $('message').textContent = text; };
  const reset = () => {
    epoch++;
    if (pending) pending.abort();
    pending = null;
    bearer = '';
    bindings = [];
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
    catch { throw new Error('Unexpected response. Refresh status before retrying a change.'); }
    if (!response.ok) {
      const errors = {401: 'Entry authentication rejected or expired. Connect again with a valid entry credential.', 403: 'Request denied. Check the page address and your permissions.', 409: 'Binding changed. Refresh status before trying again.', 400: 'Invalid request. Check the credential and expiry.', 503: 'State unavailable. Refresh status before retrying; do not assume the change failed.'};
      throw new Error(errors[response.status] || 'Request failed. Refresh status before retrying.');
    }
    return data;
  }
  function render(data) {
    bindings = data.bindings;
    $('identity').textContent = 'Signed in as ' + data.principal + ' (' + data.tenant + ')';
    const previous = $('system').value;
    $('bindings').replaceChildren();
    $('system').replaceChildren();
    for (const binding of bindings) {
      const item = document.createElement('li');
      item.textContent = binding.system + ': ' + binding.state + (binding.expires_at ? ' · expires ' + new Date(binding.expires_at).toLocaleString() : '') + (binding.hint ? ' · ' + binding.hint : '');
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
    catch (error) { if (current === epoch && error.name !== 'AbortError') message(error instanceof TypeError ? 'Connection interrupted. Refresh status before retrying a change.' : error.message); }
    finally { if (current === epoch) { busy = false; pending = null; controls(); } }
  }
  async function refresh(signal, current) {
    const data = await request('/account/api/bindings', undefined, signal);
    if (current !== epoch) return;
    render(data);
    message('Status loaded. Credentials are never returned.');
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
  $('disconnect').addEventListener('click', () => { reset(); message('Disconnected. Page credentials cleared. An already-submitted change may have completed; reconnect to check.'); });
  $('binding-form').addEventListener('submit', event => {
    event.preventDefault();
    if (busy) return;
    const binding = bindings.find(item => item.system === $('system').value);
    if (!binding) return;
    const body = {expected_generation: binding.generation, credential: $('credential').value};
    if ($('expiry').value) {
      const date = new Date($('expiry').value);
      if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) { message('Choose a future expiry.'); return; }
      body.expires_at = date.toISOString();
    }
    $('credential').value = '';
    perform(async (signal, current) => {
      const result = await request('/account/api/bindings/' + encodeURIComponent(binding.system), body, signal);
      body.credential = '';
      if (current !== epoch) return;
      await refresh(signal, current);
      if (current === epoch) message(result.hint || 'Replacement saved.');
    }).finally(() => { body.credential = ''; });
  });
  $('revoke').addEventListener('click', () => {
    if (busy) return;
    const binding = bindings.find(item => item.system === $('system').value);
    if (!binding || !window.confirm('Revoke your ' + binding.system + ' binding?')) return;
    perform(async (signal, current) => {
      await request('/account/api/bindings/' + encodeURIComponent(binding.system) + '/revoke', {expected_generation: binding.generation}, signal);
      if (current !== epoch) return;
      await refresh(signal, current);
      if (current === epoch) message('Binding revoked.');
    });
  });
  window.addEventListener('pagehide', reset);
})();

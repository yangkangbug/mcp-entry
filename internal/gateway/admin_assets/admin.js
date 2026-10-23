'use strict';
(() => {
    const $ = id => document.getElementById(id);
    // The snapshot is server-owned running state; drafts are page-local and never active config.
    // epoch invalidates an entire connection; viewRevision invalidates a UI preview only.
    const state = {
      lang:'zh-CN',
      page:'overview',
      viewRevision:0,
      token:'',
      epoch:0,
      busy:false,
      snapshot:null,
      userKey:'',
      serviceName:'',
      policySearch:'',
      preview:null,
      audit:null,
      draft:null,
      policyDraft:null,
      configForm: {},
      notice:null
    };
    const pages = {
      overview:['概览',
        'Overview',
        '一个入口，连接获准使用的 MCP 服务。先配置服务，再管理身份与工具授权。',
        'One gateway for authorized MCP services. Configure services, then manage identities and tool access.'],
      services:['MCP 服务',
        'MCP services',
        '固定服务端点与认证方式。配置、凭据和发现状态分别呈现。',
        'Fixed endpoints and authentication modes. Configuration, credentials and discovery are separate.'],
      users:['用户与入口 token',
        'Users & gateway tokens',
        '入口 token 识别用户；服务凭据仅用于连接对应服务，不能增加权限。',
        'Gateway tokens identify users. Provider credentials connect a service; they never grant more permissions.'],
      policy:['工具与授权',
        'Tools & access',
        '以完整工具名明确授权。保存白名单不会自动发现工具，也不会绑定服务凭据。',
        'Authorize exact tool names. A policy update does not discover tools or bind provider credentials.'],
      audit:['运行与审计',
        'Operations & audit',
        '查看有限保留的真实事件，不将样本包装成全站成功率。',
        'Inspect retained events, without presenting samples as a global success rate.'],
      config:['配置与维护',
        'Configuration',
        '准备接入草稿并静态校验。校验不联网、不应用配置，也不重启网关。',
        'Prepare and statically validate a draft. Validation does not connect, apply or restart.']
    };
    const text = (zh,
      en) => state.lang === 'en' ? en : zh;
    const copy = {
      operator:['管理控制台',
        'Operator console'],
      workspace:['工作空间',
        'WORKSPACE'],
      preview:['原型 · 仅合成验证',
        'Synthetic preview'],
      plane:['管理接入与授权，不代替用户的 MCP 客户端。',
        'Manage connections and access, not the user’s MCP client.'],
      disconnected:['未连接',
        'Disconnected'],
      refresh:['刷新',
        'Refresh'],
      disconnect:['断开',
        'Disconnect'],
      connectTitle:['连接管理平面',
        'Connect to the management plane'],
      connectHelp:['使用启动时 -admin-token-file 指定的独立管理员 token；向实例运营者取得，不是用户网关 token 或服务凭据。仅保留在页面内存，断开后清除。',
        'Use the separate administrator token from the startup -admin-token-file; obtain it from the instance operator. Not a user gateway token or provider credential. Page memory only; cleared on disconnect.'],
      adminToken:['管理员 token',
        'Administrator token'],
      connect:['连接',
        'Connect'],
      footer:['秘密不进入 URL、浏览器持久存储或管理报表。服务状态是有限范围的观察，不是实时可用性承诺。',
        'Secrets stay out of URLs, persistent browser storage and reports. Service status is a scoped observation, not an uptime guarantee.']
    };
    function el(tag, content, cls) {
      const n=document.createElement(tag);
      if(content!==undefined)n.textContent=String(content);
      if(cls)n.className=cls;
      return n;
    }
    function append(parent, ...children) {
      children.filter(Boolean).forEach(c=>parent.appendChild(c));
      return parent;
    }
    function button(label, fn, cls, disabled=false) {
      const b=el('button',
        label,
        cls);
      b.type='button';
      b.disabled=disabled;
      b.addEventListener('click',
        fn);
      return b;
    }
    function timestamp(value) {
      if(!value||String(value).startsWith('0001-'))return text('未设置 / 未记录', 'Not set / not recorded');
      const date=new Date(value);
      if(Number.isNaN(date.getTime()))return text('时间格式未知', 'Unknown time format');
      return new Intl.DateTimeFormat(state.lang, {timeZone:'UTC', year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hourCycle:'h23'}).format(date)+' UTC';
    }
    function timeDetail(value, expiry=false) {
      const wrap=el('div', timestamp(value));
      if(value&&!String(value).startsWith('0001-')) {
        const date=new Date(value);
        if(expiry&&!Number.isNaN(date.getTime())) {
          const days=Math.ceil((date.getTime()-Date.now())/86400000);
          wrap.appendChild(el('small', days<=0?text(' · 已到期',' · Expired'):text(' · 约 '+days+' 天后到期',' · Expires in about '+days+' days')));
        }
        const details=el('details');
        append(details, el('summary', text('原始时间','Original timestamp')), el('code', value));
        wrap.appendChild(details);
      }
      return wrap;
    }
    function help(title, content) {
      return append(el('details'), el('summary', title), el('p', content, 'muted'));
    }
    function bindingState(value) {
      const labels= {
        active:['已保存',
          'Stored'],
        unbound:['未绑定',
          'Unbound'],
        revoked:['已撤销',
          'Revoked'],
        expired:['已过期',
          'Expired']
      };
      return labels[value]?text(...labels[value]):value;
    }
    function badge(label, kind) {
      return el('span',
        label,
        'badge '+(kind||''));
    }
    function panel(title, description) {
      const p=el('section',
        undefined,
        'panel');
      append(p,
        el('h2',
          title),
        description&&el('p',
          description,
          'muted'));
      return p;
    }
    function note(zh, en) {
      return el('p',
        text(zh,
          en),
        'note');
    }
    function metric(label, value, help) {
      const p=el('div',
        undefined,
        'metric');
      append(p,
        el('span',
          label,
          'muted'),
        el('strong',
          value??'—',
          'metric-value'),
        el('small',
          help));
      return p;
    }
    function empty(parent, zh, en) {
      const p=el('div',
        text(zh,
          en),
        'empty');
      parent.appendChild(p);
    }
    function table(headers, rows) {
      const wrap=el('div',
        undefined,
        'table-wrap'),
      tbl=el('table'),
      head=el('thead'),
      tr=el('tr');
      headers.forEach(h=>tr.appendChild(el('th',
            h)));
      head.appendChild(tr);
      tbl.appendChild(head);
      const body=el('tbody');
      rows.forEach(row=> {
          const r=el('tr');
          row.forEach(v=> {
              const td=el('td');
              td.appendChild(v&&typeof v==='object'&&v.nodeType?v:el('span',
                  v??'—'));
              r.appendChild(td)
          });
          body.appendChild(r)
      });
      tbl.appendChild(body);
      wrap.appendChild(tbl);
      return wrap;
    }
    function notify(zh, en, error=false) {
      state.notice= {
        zh,
        en,
        error
      };
      renderNotice();
    }
    function renderNotice() {
      const n=$('message');
      n.replaceChildren();
      if(state.notice) {
        n.className=state.notice.error?'status-box error':'status-inline';
        n.textContent=text(state.notice.zh,
          state.notice.en)
      }else n.className='';
    }
    function capability(name) {
      return !!state.snapshot?.capabilities?.[name];
    }
    // Leaving and returning to a page must not revive an in-flight preview for an older view.
    function navigate(page) {
      state.viewRevision++;
      state.page=page;
      state.preview=null;
      state.policyDraft=null;
      render();
    }
    function user() {
      return (state.snapshot?.users||[]).find(u=>key(u)===state.userKey);
    }
    function key(u) {
      return JSON.stringify([u.tenant,
          u.principal]);
    }
    function userPicker(parent) {
      const users=state.snapshot?.users||[];
      if(!users.length) {
        empty(parent,
          '尚无已配置用户。新增身份需要离线配置与拓扑迁移支持。',
          'No configured users. New identities require offline configuration and topology migration support.');
        return null;
      }
      if(!user())state.userKey=key(users[0]);
      const label=el('label',
        text('选择身份',
          'Select identity'));
      label.htmlFor='identity-select';
      const sel=el('select');
      sel.id='identity-select';
      users.forEach(u=> {
          const o=el('option',
            u.tenant+' / '+u.principal);
          o.value=key(u);
          sel.appendChild(o)
      });
      sel.value=state.userKey;
      sel.disabled=state.busy;
      sel.addEventListener('change',
        ()=> {
          state.viewRevision++;
          state.userKey=sel.value;
          state.preview=null;
          state.policyDraft=null;
          state.policySearch='';
          render()
      });
      append(parent,
        label,
        sel);
      return user();
    }
    function setBusy(value) {
      state.busy=value;
      render();
    }
    // Secrets have page-memory lifetime only. Clear state before any late response can arrive.
    function disconnect() {
      state.epoch++;
      state.token='';
      state.busy=false;
      state.snapshot=null;
      state.audit=null;
      state.preview=null;
      state.policyDraft=null;
      state.draft=null;
      state.configForm= {
      };
      state.userKey='';
      state.serviceName='';
      state.policySearch='';
      state.notice=null;
      $('admin-token').value='';
      render();
    }
    // Check the connection epoch after both awaits: disconnect can happen during JSON decoding.
    async function request(path, body) {
      const epoch=state.epoch;
      const options= {
        method:body===undefined?'GET':'POST',
        credentials:'omit',
        cache:'no-store',
        redirect:'error',
        headers: {
          Authorization:'Bearer '+state.token
        }
      };
      if(body!==undefined) {
        options.headers['Content-Type']='application/json';
        options.headers['X-MCP-Admin']='1';
        options.body=JSON.stringify(body);
      }
      const response=await fetch('/admin/api/'+path,
        options);
      if(epoch!==state.epoch)throw {
        stale:true
      };
      let result;
      try {
        result=await response.json()
      }catch {
        throw {
          code:'invalid_response'
        }
      }
      if(epoch!==state.epoch)throw {
        stale:true
      };
      if(!response.ok)throw {
        code:result.error||'request_failed',
        status:response.status
      };
      return result;
    }
    function showError(e, write=false) {
      if(e.stale)return;
      if(e.status===401) {
        disconnect();
        notify('管理员认证失效。请重新连接。',
          'Administrator authentication expired or was rejected. Reconnect.',
          true);
        return;
      }
      if(e.code==='invalid_configuration') {
        notify('草稿未通过校验。请核对服务 ID、固定端点、认证头与网络允许 IP。未应用任何配置。',
          'Draft validation failed. Check service IDs, fixed endpoints, authentication headers and allowed IPs. No configuration was applied.',
          true);
        return;
      }
      if(e.status===409) {
        state.preview=null;
        notify('版本已变化，未应用此修改。请刷新状态并重新预览。',
          'Version changed; this change was not applied. Refresh and preview again.',
          true);
      }else if(write) {
        state.preview=null;
        notify('未能确认操作结果。请刷新并核对状态；不要直接重复提交。',
          'Could not confirm the outcome. Refresh and verify state; do not repeat the submission.',
          true);
      }else notify('请求未完成。请检查管理员权限和服务状态，再刷新。',
        'Request did not complete. Check administrator access and service status, then refresh.',
        true);
    }
    async function refresh() {
      if(state.busy||!state.token)return;
      const epoch=state.epoch;
      setBusy(true);
      try {
        state.snapshot=await request('snapshot');
        state.preview=null;
        notify('已读取当前管理状态。',
          'Current management state loaded.');
      }catch(e) {
        showError(e)
      }finally {
        if(epoch===state.epoch)setBusy(false);
      }
    }
    // Preview is not a reservation. Confirmation sends the same expected version for backend CAS.
    // Unknown write outcomes are never replayed; refresh and inspect authoritative state instead.
    async function mutate(body, confirm) {
      if(state.busy)return;
      const epoch=state.epoch;
      const context=state.userKey;
      const page=state.page;
      const viewRevision=state.viewRevision;
      setBusy(true);
      let committed=false;
      try {
        const result=await request('mutate',
          {
            ...body,
            preview:!confirm,
            ...(confirm? {
                confirm:true
              }
              : {
            })
        });
        if(confirm&&result.applied!==true||!confirm&&result.preview!==true)throw {
          code:'invalid_response'
        };
        if(confirm) {
          committed=true;
          state.preview=null;
          state.snapshot=await request('snapshot');
          state.policyDraft=null;
          notify('修改已提交，状态已刷新。',
            'Change committed and state refreshed.');
        }else if(context===state.userKey&&page===state.page&&viewRevision===state.viewRevision) {
          state.preview=body;
          notify('预览已通过。请核对下方对象与变更后确认。',
            'Preview passed. Review the target and change below before confirming.');
        }
      }catch(e) {
        if(committed&&!e.stale&&e.status!==401)notify('修改已提交，但状态刷新失败。请刷新核对，不要重复提交。',
          'Change committed, but state refresh failed. Refresh to verify; do not resubmit.',
          true);
        else showError(e,
          confirm)
      }finally {
        if(epoch===state.epoch)setBusy(false);
      }
    }
    function confirmation(parent) {
      if(!state.preview)return;
      const b=state.preview;
      const p=panel(text('确认变更',
          'Confirm change'));
      p.id='mutation-confirmation';
      append(p,
        el('p',
          b.tenant+' / '+b.principal),
        el('p',
          text('操作：',
            'Action: ')+b.action+(b.system?' · '+b.system:'')),
        el('p',
          text('预期版本：',
            'Expected version: ')+b.expected_version));
      if(b.action==='disable_principal')p.appendChild(note('禁用后该用户不能继续使用网关。当前管理台没有重新启用操作，请先确认维护恢复路径。',
          'Disabling blocks this user from the gateway. This console has no re-enable action; confirm the maintenance recovery path first.'));
      if(b.allowed&&user())policyDiff(p,user(),b.allowed);
      if(b.allowed)append(p,
        el('pre',
          b.allowed.join('\n')||text('空白名单：移除所有工具授权',
            'Empty allowlist: remove all tool access')));
      append(p,
        note('请确认作用范围。此修改不会自动重试任何业务调用。',
          'Confirm the scope. This change never retries a business call.'),
        button(text('确认提交',
            'Confirm change'),
          ()=>mutate(b,
            true),
          'danger',
          state.busy),
        button(text('取消',
            'Cancel'),
          ()=> {
            state.preview=null;
            render()
          },
          '',
          state.busy));
      parent.appendChild(p);
    }
    function render() {
      document.documentElement.lang=state.lang;
      document.title=text('MCP Entry · 管理台',
        'MCP Entry · Admin');
      document.querySelectorAll('[data-i18n]').forEach(n=> {
          const v=copy[n.dataset.i18n];
          if(v)n.textContent=text(...v)
      });
      const nav=$('navigation');
      nav.replaceChildren();
      Object.entries(pages).forEach(([id,
            v],
          i)=> {
          const b=button(text(v[0],
              v[1]),
            ()=>navigate(id));
          if(state.page===id)b.setAttribute('aria-current',
            'page');
          nav.appendChild(b)
      });
      $('page-title').textContent=text(pages[state.page][0],
        pages[state.page][1]);
      $('page-description').textContent=text(pages[state.page][2],
        pages[state.page][3]);
      $('authentication').hidden=!!state.snapshot;
      $('connection-state').textContent=state.busy?text('处理中…',
        'Working…'):state.snapshot?text('管理连接已建立 · 存储：',
        'Management connected · Storage: ')+text(state.snapshot.persistent?'持久模式':'内存模式',
        state.snapshot.persistent?'Persistent':'In memory'):text('未连接',
        'Disconnected');
      $('connection-state').className='badge'+(state.snapshot?' good':'');
      $('refresh').disabled=state.busy||!state.snapshot;
      $('disconnect').disabled=!state.token;
      $('connect').disabled=state.busy;
      $('admin-token').disabled=state.busy;
      renderNotice();
      const c=$('content');
      c.replaceChildren();
      c.setAttribute('aria-busy',
        String(state.busy));
      if(!state.snapshot) {
        renderIntro(c);
        return;
      }( {
          overview:renderOverview,
          services:renderServices,
          users:renderUsers,
          policy:renderPolicy,
          audit:renderAudit,
          config:renderConfig
      })[state.page](c);
    }
    function renderIntro(c) {
      const p=panel(text('让服务接入可管理，让用户只用一个入口',
          'Manage services. Give users one gateway.'),
        text('这是运营管理平面，不是员工绑定页面。连接后可查看真实配置、授权与运行记录。',
          'This is the operator plane, not an employee binding page. Connect to inspect actual configuration, access and operations.'));
      p.classList.add('hero');
      const flow=el('div',
        undefined,
        'route');
      append(flow,
        el('span',
          text('MCP 客户端',
            'MCP client')),
        el('b',
          '→'),
        el('span',
          'MCP Entry'),
        el('b',
          '→'),
        el('span',
          text('获准的服务',
            'Authorized services')));
      p.appendChild(flow);
      c.appendChild(p);
    }
    function serviceFacts(service, u) {
      return {binding:u?.bindings?.find(b=>b.system===service.name), tools:(u?.tools||[]).filter(t=>t.system===service.name)};
    }
    function serviceTable(u) {
      return table([text('服务','Service'),text('凭据绑定','Credential binding'),text('已发现 / 当前获准工具','Discovered / currently allowed tools'),text('查看','Inspect')],
        state.snapshot.services.map(service=> {
          const {binding,tools}=serviceFacts(service,u);
          return [append(el('div'),el('strong',service.name),el('small',text('已配置 · 认证健康未检查','Configured · Auth health not checked'))),
            !u?text('未选择身份','No identity selected'):binding?bindingState(binding.state):text('无绑定记录','No binding record'),
            !u?'—':tools.length+' / '+tools.filter(t=>t.authorized).length,
            button(text('查看服务','View service')+' · '+service.name,()=>{state.serviceName=service.name;navigate('services');})];
        }));
    }
    function renderOverview(c) {
      if(!state.snapshot.services.length) {
        const p=panel(text('接入第一个 MCP 服务','Connect your first MCP service'),text('先生成并校验本地草稿；在线应用尚未开放。','Start with a local draft. Online application is not available.'));
        p.classList.add('hero');
        append(p,button(text('准备接入配置','Prepare service configuration'),()=>navigate('config'),'primary'));
        c.appendChild(p);
      }else {
        const p=panel(text('服务概况','Service overview'),text('以下绑定与目录仅属于所选身份。目录是保留的发现结果，不代表实时在线。','Bindings and catalogs below belong only to the selected identity. Retained discovery is not live uptime.'));
        const u=userPicker(p);
        p.appendChild(serviceTable(u));c.appendChild(p);
        const attention=panel(text('需要关注','Needs attention'));
        if(u) {
          const items=[];
          if(u.disabled)items.push(text('此身份已禁用，不能继续使用网关。','This identity is disabled and cannot use the gateway.'));
          state.snapshot.services.forEach(service=> {
            const {binding,tools}=serviceFacts(service,u);
            if(!binding||binding.state!=='active')items.push(service.name+' · '+(binding?bindingState(binding.state):text('无绑定记录','No binding record')));
            if(!tools.length)items.push(service.name+' · '+text('尚无发现目录；不能据此判断无授权或服务故障。','No discovery catalog; this does not establish missing access or a service failure.'));
          });
          const absent=(u.allowed||[]).filter(name=>!(u.tools||[]).some(t=>t.name===name));
          if(absent.length)items.push(text('有 '+absent.length+' 项授权暂未在目录中发现，仍予保留。',absent.length+' allowed tools are absent from discovery and remain retained.'));
          if(items.length)append(attention,...items.map(v=>el('p',v)));
          else attention.appendChild(el('p',text('当前快照没有上述待处理事项；认证健康仍未检查。','No listed attention items in this snapshot; authentication health remains unchecked.')));
        }else empty(attention,'尚无身份，无法观察绑定与目录。','No identity is available to inspect bindings and catalogs.');
        append(attention,button(text('管理工具授权','Manage tool access'),()=>navigate('policy')),button(text('准备接入配置','Prepare service configuration'),()=>navigate('config')));
        c.appendChild(attention);
      }
      c.appendChild(help(text('运行范围与尚未采集的指标','Operating scope and unavailable metrics'),text('P95 延迟尚未采集；全站成功率缺少完整分母与时间窗口。已保存凭据不证明认证有效。'+(state.snapshot.persistent?'持久状态开启；拓扑变更仍需迁移。':'内存存储：重启会丢失动态状态。'),'P95 is not collected; global success rate lacks a complete denominator and window. Stored credentials do not prove authentication. '+(state.snapshot.persistent?'Persistent state; topology changes still require migration.':'In-memory storage loses dynamic state on restart.'))));
    }
    function renderServices(c) {
      const p=panel(text('已配置服务','Configured services'),text('按身份查看绑定与目录；认证健康未检查。','Inspect bindings and discovery by identity; authentication health is not checked.'));
      const u=userPicker(p);
      if(!state.snapshot.services.length)empty(p,'尚未配置 MCP 服务。先准备配置草稿。','No MCP services configured. Prepare a draft first.');
      else p.appendChild(serviceTable(u));
      p.appendChild(button(text('准备接入配置','Prepare service configuration'),()=>navigate('config')));
      c.appendChild(p);
      const service=state.snapshot.services.find(s=>s.name===state.serviceName);
      if(!service)return;
      const d=panel(text('服务详情 · ','Service details · ')+service.name);
      d.id='service-detail';
      const {binding,tools}=serviceFacts(service,u);
      append(d,el('p',text('身份范围：','Identity scope: ')+(u?u.tenant+' / '+u.principal:text('未选择','Not selected'))),
        el('p',text('固定端点：','Fixed endpoint: ')+service.endpoint,'break-word'),
        el('p',text('认证方式：','Authentication: ')+(service.auth?.mode||'bearer')+(service.auth?.header?' / '+service.auth.header:'')),
        el('p',text('配置已存在；认证健康未检查，没有最近检查时间或错误类别证据。','Configuration exists; auth health is not checked. No last-check timestamp or error-category evidence is available.')));
      if(u) {
        append(d,el('h3',text('此身份的凭据绑定','Credential binding for this identity')),el('p',binding?bindingState(binding.state)+text(' · 凭证版本 ',' · Credential version ')+binding.generation:text('无绑定记录','No binding record')));
        if(binding)d.appendChild(timeDetail(binding.expires_at,true));
        d.appendChild(el('h3',text('此身份的工具目录','Tool catalog for this identity')));
        if(!tools.length)empty(d,'尚无发现目录，不等于没有授权。','No discovered catalog; this does not mean no access was granted.');
        else d.appendChild(table([text('完整工具名','Exact tool name'),text('白名单','Allowlist'),text('当前访问判定','Current access decision')],tools.map(t=>[t.name,(u.allowed||[]).includes(t.name)?text('明确列入','Listed'):text('未列入','Not listed'),t.authorized?text('获准','Allowed'):text('未获准','Not allowed')])));
        d.appendChild(button(text('管理此身份授权','Manage access for this identity'),()=>navigate('policy')));
      }
      append(d,button(text('查看运行与审计','View operations & audit'),()=>navigate('audit')),el('small',text('审计入口展示保留事件样本，不按此服务筛选。','Audit shows retained event samples, not a service-filtered view.')));
      c.appendChild(d);
    }
    function renderUsers(c) {
      const p=panel(text('身份与入口凭证','Identity & gateway credential'));
      const u=userPicker(p);c.appendChild(p);if(!u)return;
      const entry=u.entry;
      const expired=entry?.expires_at&&!entry.expires_at.startsWith('0001-')&&new Date(entry.expires_at).getTime()<=Date.now();
      const entryState=!entry?text('未提供入口信息','Entry information unavailable'):entry.revoked?text('已撤销','Revoked'):expired?text('已到期','Expired'):text('未撤销；完整可用性未确认','Not revoked; full usability unconfirmed');
      append(p,table([text('租户 / 身份','Tenant / identity'),text('身份状态','Identity state'),text('入口凭证版本','Gateway credential version'),text('入口凭证状态','Gateway credential state'),text('到期时间','Expiry')],
        [[u.tenant+' / '+u.principal,badge(u.disabled?text('已禁用','Disabled'):text('允许使用网关（仍需通过认证与授权）','Enabled (authentication and authorization still required)'),u.disabled?'bad':''),entry?.generation??'—',entryState,timeDetail(entry?.expires_at,true)]]),
        help(text('如何颁发或替换入口凭证？','How do I issue or rotate gateway credentials?'),text('使用受信离线维护流程。此管理台不显示或生成入口秘密；新增用户仍需要拓扑迁移支持。','Use trusted offline maintenance. This console does not display or generate entry secrets; new users require topology migration support.')));
      const b=panel(text('服务凭据绑定','Provider credential bindings'),text('仅显示元数据。凭据已保存不等于认证有效，目录也不是实时健康检查。','Metadata only. Stored credentials do not prove authentication; catalogs are not live health checks.'));
      if(!u.bindings?.length)empty(b,'尚无绑定记录。可显式启用本机 CLI 合成绑定；原生客户端集成尚未验证。','No binding records. Opt-in local CLI synthetic binding is available; native client integration is unverified.');
      else b.appendChild(table([text('服务','Service'),text('凭据状态','Credential state'),text('凭证版本','Credential version'),text('到期','Expires'),text('已发现工具','Discovered tools')],u.bindings.map(x=>[x.system,bindingState(x.state),x.generation,timeDetail(x.expires_at,true),(u.tools||[]).filter(t=>t.system===x.system).length])));
      c.appendChild(b);
      const danger=panel(text('危险操作','Danger zone'),text('禁用身份将阻止其继续使用网关，当前页面无法重新启用。撤销绑定将移除此身份对应服务的凭据。操作均需预览并再次确认。','Disabling blocks gateway access and cannot be undone here. Revoking a binding removes this identity’s credential for that service. Both require preview and explicit confirmation.'));
      danger.classList.add('danger-zone');
      append(danger,button(text('预览禁用此用户','Preview disabling user'),()=>mutate({action:'disable_principal',tenant:u.tenant,principal:u.principal,expected_version:u.policy_version},false),'danger',state.busy||u.disabled||!capability('principal_disable')));
      (u.bindings||[]).forEach(x=>danger.appendChild(button(text('预览撤销','Preview revoke')+' · '+x.system,()=>mutate({action:'revoke_binding',tenant:u.tenant,principal:u.principal,system:x.system,expected_version:x.generation},false),'danger',state.busy||!capability('binding_revoke')||x.state==='revoked')));
      c.appendChild(danger);confirmation(c);
    }
    function policyNames(u) {
      return [...new Set((state.policyDraft??(u.allowed||[]).join('\n')).split(/\r?\n/).map(x=>x.trim()).filter(Boolean))];
    }
    function policyDiff(parent, u, selected) {
      const before=u.allowed||[];
      const added=selected.filter(n=>!before.includes(n)), removed=before.filter(n=>!selected.includes(n));
      append(parent,el('p',text('已选 '+selected.length+' 项 · 新增 '+added.length+' · 移除 '+removed.length,'Selected '+selected.length+' · Added '+added.length+' · Removed '+removed.length)));
      if(added.length)append(parent,el('h3',text('新增授权','Added access')),el('pre',added.join('\n')));
      if(removed.length)append(parent,el('h3',text('移除授权','Removed access')),el('pre',removed.join('\n')));
    }
    function renderPolicy(c) {
      const p=panel(text('工具授权','Tool access'),text('搜索与勾选仅修改本地草稿；先预览差异，再确认提交。','Search and selection only edit a local draft; preview changes before confirming.'));
      const u=userPicker(p);c.appendChild(p);if(!u)return;
      const disabled=state.busy||!capability('policy_update');
      if(!capability('policy_update'))p.appendChild(note('当前后端未开放策略修改。','Policy editing is not available in this backend.'));
      const searchLabel=el('label',text('搜索工具或服务','Search tools or services'));
      searchLabel.htmlFor='policy-search';
      const search=el('input');search.id='policy-search';search.type='search';search.value=state.policySearch;
      const list=el('div');list.id='policy-tools';
      const diff=el('div');diff.id='policy-diff';diff.setAttribute('aria-live','polite');
      const advanced=el('details');
      append(advanced,el('summary',text('高级：编辑完整工具名','Advanced: edit exact tool names')));
      const label=el('label',text('每行一个完整工具名；空列表移除全部授权。','One exact tool name per line; an empty list removes all access.'));label.htmlFor='policy-allowed';
      const area=el('textarea');area.id='policy-allowed';area.value=state.policyDraft??(u.allowed||[]).join('\n');area.disabled=disabled;
      function changed() {
        state.viewRevision++;state.preview=null;$('mutation-confirmation')?.remove();
        diff.replaceChildren();policyDiff(diff,u,policyNames(u));
      }
      function renderTools() {
        list.replaceChildren();
        const selected=policyNames(u), known=u.tools||[], query=state.policySearch.trim().toLowerCase();
        const groups=new Map();
        known.forEach(t=>{if(!groups.has(t.system))groups.set(t.system,[]);groups.get(t.system).push(t.name);});
        const absent=[...new Set([...(u.allowed||[]),...selected])].filter(n=>!known.some(t=>t.name===n));
        if(absent.length)groups.set(null,absent);
        let matches=0;
        groups.forEach((names,system)=> {
          const visible=names.filter(name=>(name+' '+(system||'')).toLowerCase().includes(query));
          if(!visible.length)return;matches+=visible.length;
          const group=el('fieldset'),title=el('legend',system??text('未发现目录中的授权（保留）','Access absent from discovery (retained)'));
          group.appendChild(title);
          if(system===null)group.appendChild(el('p',text('目录缺失不会删除已有授权。取消勾选才会在确认后移除。','Missing discovery never removes existing access. Uncheck and confirm to remove it.'),'muted'));
          visible.forEach(name=> {
            const row=el('label',undefined,'tool-option'),box=el('input');box.type='checkbox';box.checked=selected.includes(name);box.disabled=disabled;
            box.addEventListener('change',()=> {
              const values=new Set(policyNames(u));if(box.checked)values.add(name);else values.delete(name);
              state.policyDraft=[...values].join('\n');area.value=state.policyDraft;changed();
            });
            append(row,box,el('span',name));group.appendChild(row);
          });list.appendChild(group);
        });
        if(!matches)empty(list,'没有匹配工具。已有选择仍保留；可调整搜索或使用高级模式。','No matching tools. Existing selection is retained; change the search or use advanced mode.');
      }
      search.addEventListener('input',()=>{state.policySearch=search.value;renderTools();});
      area.addEventListener('input',()=>{state.policyDraft=area.value;changed();renderTools();});
      append(advanced,label,area);
      append(p,el('p',text('当前策略版本：','Current policy version: ')+u.policy_version),searchLabel,search,list,diff,advanced,
        button(text('预览授权变更','Preview access change'),()=>mutate({action:'set_policy',tenant:u.tenant,principal:u.principal,expected_version:u.policy_version,allowed:policyNames(u)},false),'primary',disabled));
      renderTools();policyDiff(diff,u,policyNames(u));confirmation(c);
    }
    async function loadAudit() {
      if(state.busy)return;
      const epoch=state.epoch;
      setBusy(true);
      try {
        state.audit=await request('audit',
          {
            after:0,
            limit:100
        });
        notify('已读取保留事件样本（最多 100 条）。',
          'Retained event sample loaded (up to 100).');
      }catch(e) {
        showError(e)
      }finally {
        if(epoch===state.epoch)setBusy(false);
      }
    }
    function renderAudit(c) {
      const a=state.snapshot.audit|| {
      };
      const m=el('div',
        undefined,
        'metrics');
      [['待提交审计',
          'Pending audit',
          'pending'],
        ['审计容量',
          'Audit capacity',
          'capacity'],
        ['丢弃事件',
          'Dropped events',
          'dropped'],
        ['未完成事件',
          'Unfinished events',
          'unfinished']].forEach(([zh,
            en,
            k])=>m.appendChild(metric(text(zh,
              en),
            a[k]??'—',
            text('审计存储快照',
              'Audit storage snapshot'))));
      c.appendChild(m);
      const p=panel(text('保留事件',
          'Retained events'),
        text('最多读取前 100 条保留事件；不代表完整历史。未知结果不得自动重放。',
          'Reads up to the first 100 retained events, not complete history. Unknown outcomes must never be replayed automatically.'));
      append(p,
        button(text('读取事件',
            'Load events'),
          loadAudit,
          '',
          state.busy));
      if(state.audit) {
        p.appendChild(el('p',
            text('已丢弃：',
              'Dropped: ')+state.audit.dropped+' · '+text('最后序号：',
              'Last sequence: ')+state.audit.last_sequence));
        if(!state.audit.events?.length)empty(p,
          '当前保留范围内没有事件，不代表历史没有错误。',
          'No events in retained scope; this does not mean there were no past errors.');
        else p.appendChild(table([text('时间 / 序号',
                'Time / sequence'),
              text('操作 / 阶段',
                'Action / phase'),
              text('结果',
                'Result'),
              text('耗时',
                'Duration')],
            state.audit.events.map(e=>[append(el('div'),timeDetail(e.time),el('small',String(e.sequence))),
                e.action+' / '+e.phase,
                e.outcome_unknown?text('结果未知，不自动重放',
                  'Unknown outcome; no automatic replay'):e.result_class+(e.tool_is_error?text(' · 工具业务错误',
                    ' · Tool business error'):''),
                e.duration_ms+' ms'])));
      }
      c.appendChild(p);
      const r=state.snapshot.rejections;
      const q=panel(text('拒绝摘要',
          'Rejection summary'),
        text('仅当前进程观察范围，重启清零。HTTP 与操作计数单位不同，不相加为总请求量。',
          'Current-process observations only; resets on restart. HTTP and operation counts have different units and cannot be added into total requests.'));
      if(r)append(q,
        append(el('div'), el('span',text('观察起点：','Observation start: ')),timeDetail(r.Started)),
        table([text('范围 / 类别',
              'Scope / category'),
            text('次数',
              'Count'),
            text('最近时间',
              'Last observed'),
            text('计数饱和',
              'Saturated')],
          [...(r.HTTP||[]).map((x,
                i)=>['HTTP / '+text(['全局限流',
                    '身份限流',
                    '认证',
                    '授权',
                    '请求无效',
                    '不可用'][i],
                  ['Global rate limit',
                    'Principal rate limit',
                    'Authentication',
                    'Authorization',
                    'Invalid request',
                    'Unavailable'][i]),
                x.Count,
                timeDetail(x.Last),
                x.Saturated?text('是',
                  'Yes'):text('否',
                  'No')]),
            ...(r.Operations||[]).map((x,
                i)=>[text('操作 / ',
                  'Operation / ')+text(['授权',
                    '参数',
                    '准入',
                    '协议'][i],
                  ['Authorization',
                    'Arguments',
                    'Admission',
                    'Protocol'][i]),
                x.Count,
                timeDetail(x.Last),
                x.Saturated?text('是',
                  'Yes'):text('否',
                  'No')])]));
      else empty(q,
        '摘要未提供。',
        'Summary unavailable.');
      c.appendChild(q);
    }
    // The structured form builds a local draft. Validation deliberately cannot apply or restart.
    function renderConfig(c) {
      const p=panel(text('生成并校验配置草稿 · 未应用',
          'Generate and validate configuration draft · Not applied'),
        text('从当前配置生成本地草稿。此页不能在线接入、保存生效或重启；静态校验只检查格式与规则。不能包含 token 或凭据，草稿仅在页面内存保留。',
          'Prepare a local draft from running configuration. This page cannot connect, apply or restart; validation checks static rules only. No tokens or credentials. Page memory only.'));
      const fields=el('div',
        undefined,
        'fields');
      const values=state.configForm;
      function field(id, zh, en, placeholder) {
        const w=el('div'),
        l=el('label',
          text(zh,
            en)),
        i=el('input');
        l.htmlFor='draft-'+id;
        i.id='draft-'+id;
        i.value=values[id]||'';
        i.placeholder=placeholder;
        i.disabled=state.busy;
        i.addEventListener('input',
          ()=> {
            values[id]=i.value
        });
        append(w,
          l,
          i);
        fields.appendChild(w);
        return i;
      }
      const name=field('name',
        '服务 ID',
        'Service ID',
        'crm'),
      endpoint=field('endpoint',
        '固定 MCP 端点（无 token）',
        'Fixed MCP endpoint (no token)',
        'https://mcp.example.test/mcp'),
      ips=field('ips',
        '允许的 IP（逗号分隔）',
        'Allowed IPs (comma-separated)',
        '203.0.113.10'),
      quota=field('quota',
        '配额主体（可选）',
        'Quota subject (optional)',
        '');
      const authWrap=el('div'),
      authLabel=el('label',
        text('认证模式',
          'Authentication mode')),
      mode=el('select');
      mode.id='draft-mode';
      authLabel.htmlFor=mode.id;
      ['bearer',
        'raw',
        'api_key'].forEach(x=> {
          const o=el('option',
            x);
          o.value=x;
          mode.appendChild(o)
      });
      mode.value=values.mode||'bearer';
      mode.disabled=state.busy;
      mode.addEventListener('change',
        ()=> {
          values.mode=mode.value
      });
      append(authWrap,
        authLabel,
        mode);
      fields.appendChild(authWrap);
      const header=field('header',
        'API-key 头名（仅 api_key 模式）',
        'API-key header (api_key mode only)',
        'X-API-Key');
      append(p,
        fields);
      const advanced=el('details');
      advanced.appendChild(el('summary',
          text('高级：检查或编辑完整草稿',
            'Advanced: inspect or edit the full draft')));
      const label=el('label',
        text('服务配置数组（systems）',
          'Service configuration array (systems)'));
      label.htmlFor='config-draft';
      const area=el('textarea');
      area.id='config-draft';
      area.rows=12;
      area.value=state.draft??JSON.stringify(state.snapshot.services.map(( {
              name,
              endpoint,
              auth,
              network,
              quota_subject,
              timeouts
          })=>( {
              name,
              endpoint,
              auth,
              ...(timeouts? {timeouts}: {}),
              ...(network? {
                  network
                }
                : {
              }),
              ...(quota_subject? {
                  quota_subject
                }
                : {
              })
        })),
        null,
        2);
      area.disabled=state.busy;
      area.addEventListener('input',
        ()=> {
          state.draft=area.value
      });
      append(advanced,
        label,
        area);
      const validate=async()=> {
        if(state.busy)return;
        let systems;
        try {
          systems=JSON.parse(area.value);
          if(!Array.isArray(systems))throw Error();
        }catch {
          notify('请输入合法的服务配置 JSON 数组。',
            'Enter a valid service configuration JSON array.',
            true);
          return;
        }
        state.draft=area.value;
        const epoch=state.epoch;
        setBusy(true);
        try {
          const r=await request('config/validate',
            {
              systems
          });
          if(r.valid&&r.applied===false)notify('静态校验通过，未应用。拓扑变更需要迁移支持；不要直接覆盖运行配置或重新初始化数据库。',
            'Static validation passed; NOT APPLIED. Topology changes require migration support. Do not overwrite running configuration or reinitialize the database.');
          else notify('后端未确认草稿有效，未声明应用成功。',
            'The backend did not confirm draft validity; no application is claimed.',
            true);
        }catch(e) {
          showError(e)
        }finally {
          if(epoch===state.epoch)setBusy(false);
        }
      };
      append(p,
        button(text('加入本地草稿',
            'Add to local draft'),
          ()=> {
            let systems;
            try {
              systems=JSON.parse(area.value);
              if(!Array.isArray(systems))throw Error();
            }catch {
              notify('请先修正下方 JSON 草稿。',
                'Fix the JSON draft below first.',
                true);
              return;
            }
            if(!name.value.trim()||!endpoint.value.trim()) {
              notify('请填写服务 ID 和固定端点。',
                'Enter a service ID and fixed endpoint.',
                true);
              return;
            }
            if(systems.some(x=>x.name===name.value.trim())||systems.length>=16) {
              notify('服务 ID 不能重复，最多 16 个服务。',
                'Service IDs must be unique; at most 16 services.',
                true);
              return;
            }
            const service= {
              name:name.value.trim(),
              endpoint:endpoint.value.trim(),
              auth: {
                mode:mode.value
              }
            };
            if(mode.value==='api_key')service.auth.header=header.value.trim();
            if(ips.value.trim())service.network= {
              allowed_ips:ips.value.split(',').map(x=>x.trim()).filter(Boolean)
            };
            if(quota.value.trim())service.quota_subject=quota.value.trim();
            systems.push(service);
            state.draft=JSON.stringify(systems,
              null,
              2);
            notify('已加入当前页面草稿，尚未校验或应用。',
              'Added to this page’s draft; not validated or applied.');
            render();
          },
          '',
          state.busy),
        note('只填写连接配置，不填写服务凭据。Bearer 自动加前缀；raw 将原值作为 Authorization；api_key 使用指定头名。HTTPS/域名端点需要允许 IP；高级 JSON 可编辑已有服务。',
          'Enter connection configuration, not provider credentials. Bearer adds the Bearer prefix; raw sends the credential as Authorization; api_key uses a named header. HTTPS/hostnames require allowed IPs. Advanced JSON supports full edits.'),
        advanced,
        button(text('静态校验草稿',
            'Validate draft'),
          validate,
          'primary',
          state.busy||!capability('config_validate')),
        note('校验成功不表示端点可用、凭据有效或持久存储能重新打开。这里没有“保存并生效”。',
          'Validation does not prove endpoint availability, credential validity or storage reopenability. There is no “save and activate” here.'));
      c.appendChild(p);
      const maintenance=panel(text('应用与维护边界',
          'Application & maintenance boundaries'));
      maintenance.appendChild(help(text('如何应用配置或重启？','How do I apply configuration or restart?'),text('当前没有受控应用执行器与拓扑迁移，不能在线应用此草稿。入口替换/撤销、根密钥轮换和审计归档使用受信离线流程。不要覆盖数据库或重新初始化绕过迁移。','There is no controlled apply executor or topology migration; this draft cannot be applied online. Use trusted offline workflows for entry lifecycle, root-key rotation and audit archival. Never overwrite or reinitialize the database to bypass migration.')));
      c.appendChild(maintenance);
    }
    $('login-form').addEventListener('submit',
      e=> {
        e.preventDefault();
        if(state.busy)return;
        const token=$('admin-token').value.trim();
        $('admin-token').value='';
        if(!token)return;
        state.epoch++;
        state.token=token;
        refresh();
    });
    $('disconnect').addEventListener('click',
      disconnect);
    $('refresh').addEventListener('click',
      refresh);
    $('language').addEventListener('change',
      ()=> {
        state.lang=$('language').value==='en'?'en':'zh-CN';
        render()
    });
    window.addEventListener('pagehide',
      disconnect);
    render();
})();

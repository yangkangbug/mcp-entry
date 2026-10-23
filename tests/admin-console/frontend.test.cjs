// Dependency-free state/DOM regression tests. Not a substitute for browser visual QA.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname,
  '../../internal/gateway/admin_assets');
const src = fs.readFileSync(path.join(root,
    'admin.js'),
  'utf8');
const html = fs.readFileSync(path.join(root,
    'index.html'),
  'utf8');
class Element {
  constructor(tag='div') {
    this.tag=tag;
    this.nodeType=1;
    this.children=[];
    this.value='';
    this.textContent='';
    this.disabled=false;
    this.handlers= {
    };
    this.dataset= {
    };
    this.attributes= {
    };
    this.className='';
    this.classList= {
      add:x=> {
        this.className+=' '+x
      }
    };
  }
  addEventListener(k,
    f) {
    this.handlers[k]=f
  }
  replaceChildren(...children) {
    this.children=[];
    children.forEach(c=>this.appendChild(c))
  }
  appendChild(c) {
    c.parent=this;
    this.children.push(c);
    return c
  }
  setAttribute(k,
    v) {
    this.attributes[k]=v
  }
  remove() {
    this.parent.children=this.parent.children.filter(x=>x!==this)
  }
  fire(k) {
    if(this.disabled)return;
    return this.handlers[k]?.( {
        preventDefault() {
        }
    })
  }
}
const elements= {
};
for(const m of html.matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)) {
  elements[m[2]]=new Element(m[1]);
  elements[m[2]].id=m[2];
  elements[m[2]].disabled=m[0].includes('disabled')
}
const walk=e=>[e,
  ...e.children.flatMap(walk)];
const all=()=>Object.values(elements).flatMap(walk);
const staticText=[...html.matchAll(/data-i18n="([^"]+)"/g)].map(m=>Object.assign(new Element(),
    {
      dataset: {
        i18n:m[1]
      }
}));
const document= {
  getElementById:id=>all().find(x=>x.id===id),
  createElement:tag=>new Element(tag),
  querySelectorAll:()=>staticText,
  documentElement: {
  }
};
const calls=[],
pending=[];
const context= {
  document,
  window: {
    handlers:{},
    addEventListener(name,fn) { this.handlers[name]=fn; }
  },
  fetch:(url,
    opts)=> {
    calls.push( {
        url,
        opts
    });
    return new Promise((resolve,
        reject)=>pending.push( {
          resolve,
          reject
    }))
  }
};
vm.runInNewContext(src,
  context);
const tick=()=>new Promise(r=>setImmediate(r));
async function respond(body,
  status=200) {
  assert.ok(pending.length,
    'expected pending request');
  pending.shift().resolve( {
      ok:status<400,
      status,
      json:async()=>body
  });
  await tick()
}
const findButton=label=>all().find(x=>x.tag==='button'&&x.textContent===label);
const click=label=> {
  const b=findButton(label);
  assert.ok(b,
    'button '+label);
  b.fire('click');
  return b
};
const content=()=>walk(elements.content).map(x=>x.textContent).join(' ');
const lang=v=> {
  elements.language.value=v;
  elements.language.fire('change')
};
const snapshot= {
  persistent:false,
  capabilities: {
    policy_update:true,
    principal_disable:true,
    binding_revoke:true,
    config_validate:true
  },
  services:[ {
      name:'crm',
      endpoint:'https://example.test/mcp',
      auth: {
        mode:'bearer'
      },
      timeouts:{discovery_ms:1234,call_ms:2345,response_header_ms:1234},
      health:'not_checked'
  }],
  users:[ {
      tenant:'t',
      principal:'<script>identity</script>',
      policy_version:2,
      allowed:['crm__read','legacy__missing'],
      disabled:false,
      entry: {
        generation:1,
        revoked:false,
        expires_at:'0001-01-01T00:00:00Z'
      },
      bindings:[ {
          system:'crm',
          generation:3,
          state:'active'
      }],
      tools:[ {
          name:'crm__read',
          system:'crm',
          authorized:true
      }]
  }],
  audit: {
    pending:0,
    capacity:4096,
    dropped:0,
    unfinished:0
  },
  rejections: {
    Started:'2026-10-23T00:00:00Z',
    HTTP:[ {
        Count:0,
        Last:'',
        Saturated:false
    }],
    Operations:[]
  }
};
async function login() {
  elements['admin-token'].value='synthetic-admin-token';
  elements['login-form'].fire('submit');
  await respond(snapshot)
} (async()=> {
    assert.equal(document.documentElement.lang,
      'zh-CN');
    assert.equal(calls.length,
      0);
    elements['admin-token'].value='synthetic-admin-token';
    lang('en');
    assert.equal(elements['admin-token'].value,
      'synthetic-admin-token');
    elements['login-form'].fire('submit');
    elements['login-form'].fire('submit');
    assert.equal(calls.length,
      1,
      'duplicate login prevented');
    assert.equal(elements['admin-token'].value,
      '');
    lang('zh-CN');
    assert.equal(calls.length,
      1,
      'language changes do not request');
    await respond(snapshot);
    assert.match(content(),
      /未采集|尚未采集/);
    assert.ok(elements.authentication.hidden);
    assert.doesNotMatch(content(), /先接入服务，再开放给用户/);
    assert.match(content(), /服务概况/);
    assert.match(content(), /暂未在目录中发现/);
    assert.equal(elements.message.className,'status-inline');
    click('查看服务 · crm');
    assert.match(content(), /服务详情 · crm/);
    assert.match(content(), /身份范围：t \/ <script>identity<\/script>/);
    assert.match(content(), /认证健康未检查/);
    assert.match(content(), /https:\/\/example.test\/mcp/);
    click('用户与入口 token');
    assert.match(content(),
      /<script>identity<\/script>/,
      'untrusted names remain literal text');
    assert.match(content(), /如何颁发或替换入口凭证/);
    assert.match(content(), /危险操作/);
    assert.doesNotMatch(content(),
      /0001-01-01/,
      'zero expiry not presented as real date');
    click('工具与授权');
    let area=document.getElementById('policy-allowed');
    assert.ok(area.value.includes('legacy__missing'),'undiscovered authorization retained');
    assert.match(content(), /未发现目录中的授权（保留）/);
    const beforeSelection=calls.length;
    let search=document.getElementById('policy-search');
    search.value='no-such-tool';search.fire('input');
    assert.match(content(), /没有匹配工具/);
    assert.ok(area.value.includes('legacy__missing'),'search must not remove missing grants');
    search.value='crm';search.fire('input');
    let check=all().find(x=>x.type==='checkbox');
    assert.ok(check.checked);check.checked=false;check.fire('change');
    assert.equal(area.value,'legacy__missing');
    assert.match(content(), /移除授权/);
    assert.equal(calls.length,beforeSelection,'search and selection are local only');
    lang('en');
    assert.equal(document.getElementById('policy-search').value,'crm');
    assert.equal(document.getElementById('policy-allowed').value,'legacy__missing');
    lang('zh-CN');area=document.getElementById('policy-allowed');
    search=document.getElementById('policy-search');
    search.value='legacy';search.fire('input');
    check=all().find(x=>x.type==='checkbox');
    assert.ok(check.checked);check.checked=false;check.fire('change');
    lang('en');
    assert.equal(all().find(x=>x.type==='checkbox').checked,false,'explicitly removed undiscovered grant stays removed across language changes');
    search=document.getElementById('policy-search');search.value='';search.fire('input');
    assert.equal(document.getElementById('policy-allowed').value,'');
    lang('zh-CN');area=document.getElementById('policy-allowed');
    area.value='crm__write';
    area.fire('input');
    lang('en');
    assert.equal(document.getElementById('policy-allowed').value,
      'crm__write');
    click('Preview access change');
    const count=calls.length;
    click('Preview access change');
    assert.equal(calls.length,
      count,
      'duplicate preview prevented');
    lang('zh-CN');
    await respond( {
        preview:true
    });
    assert.ok(findButton('确认提交'));
    const body=JSON.parse(calls.at(-1).opts.body);
    assert.equal(body.expected_version,
      2);
    assert.equal(body.preview,
      true);
    assert.equal(calls.at(-1).opts.headers['X-MCP-Admin'],
      '1');
    check=all().find(x=>x.type==='checkbox');
    const beforeCheckbox=calls.length;
    check.checked=true;check.fire('change');
    assert.equal(findButton('确认提交'),undefined,'checkbox edit invalidates preview confirmation');
    assert.equal(calls.length,beforeCheckbox,'checkbox cannot submit a write');
    click('预览授权变更');await respond({preview:true});
    assert.ok(findButton('确认提交'));
    area=document.getElementById('policy-allowed');
    area.value='crm__read';
    area.fire('input');
    assert.equal(findButton('确认提交'),
      undefined,
      'editing policy removes stale confirmation');
    click('预览授权变更');
    click('MCP 服务');
    click('工具与授权');
    await respond( {
        preview:true
    });
    assert.equal(findButton('确认提交'),
      undefined,
      'preview cannot cross page changes');
    click('预览授权变更');
    await respond( {
        preview:true
    });
    click('确认提交');
    await respond( {
        error:'version_conflict'
      },
      409);
    assert.match(elements.message.textContent,
      /版本已变化/);
    assert.equal(findButton('确认提交'),
      undefined);
    click('预览授权变更');
    await respond( {
        preview:true
    });
    click('确认提交');
    const n=calls.length;
    await respond( {
        error:'state_unavailable'
      },
      503);
    assert.equal(calls.length,
      n,
      'uncertain mutation never retried');
    assert.match(elements.message.textContent,
      /不要直接重复提交/);
    click('配置与维护');
    assert.equal(JSON.parse(document.getElementById('config-draft').value)[0].timeouts.call_ms,2345,'existing timeout settings preserved in draft');
    document.getElementById('draft-name').value='docs';
    document.getElementById('draft-endpoint').value='https://docs.example.test/mcp';
    click('加入本地草稿');
    assert.match(document.getElementById('config-draft').value,
      /docs/);
    assert.match(content(), /生成并校验配置草稿 · 未应用/);
    assert.equal(findButton('应用配置 / 重启'), undefined);
    click('静态校验草稿');
    await respond( {
        valid:true,
        applied:false
    });
    assert.match(elements.message.textContent,
      /未应用/);
    click('运行与审计');
    click('读取事件');
    await respond( {
        events:[],
        dropped:0,
        last_sequence:0
    });
    assert.match(content(), /不代表历史没有错误/);
    assert.match(content(), /2026.*10.*23.*UTC/,'readable timestamp includes explicit timezone');
    elements.refresh.fire('click');
    elements.disconnect.fire('click');
    await respond(snapshot);
    assert.equal(elements.authentication.hidden,
      false,
      'late snapshot cannot reconnect');
    assert.equal(elements.refresh.disabled,
      true);
    await login();
    elements.refresh.fire('click');
    const p=pending.shift();
    let resolveJSON;
    p.resolve( {
        ok:true,
        status:200,
        json:()=>new Promise(r=>resolveJSON=r)
    });
    await tick();
    elements.disconnect.fire('click');
    resolveJSON(snapshot);
    await tick();
    assert.equal(elements.authentication.hidden,
      false,
      'disconnect during json decode rejects stale result');
    await login();
    elements.refresh.fire('click');
    await respond( {
        error:'admin_authentication_rejected'
      },
      401);
    assert.equal(elements.authentication.hidden,
      false);
    assert.equal(elements['admin-token'].value,
      '');
    await login();
    elements.refresh.fire('click');
    await respond( {
        ...snapshot,
        capabilities: {
        }
    });
    click('工具与授权');
    assert.ok(findButton('预览授权变更').disabled);
    click('配置与维护');
    assert.ok(findButton('静态校验草稿').disabled);
    elements.refresh.fire('click');
    await respond({...snapshot,services:[],users:[]});
    click('概览');
    assert.match(content(), /接入第一个 MCP 服务/);
    elements.refresh.fire('click');
    const second={...snapshot.users[0],principal:'second',allowed:[],bindings:[],tools:[]};
    await respond({...snapshot,services:[...snapshot.services,{name:'docs',endpoint:'https://docs.example.test',auth:{mode:'raw'}},{name:'long-service-name'.repeat(12),endpoint:'https://long.example.test',auth:{mode:'bearer'}}],users:[...snapshot.users,second]});
    assert.equal(all().filter(x=>x.tag==='button'&&x.textContent.startsWith('查看服务 · ')).length,3);
    assert.doesNotMatch(content(), /接入第一个 MCP 服务/);
    click('工具与授权');
    const select=document.getElementById('identity-select');
    select.value=JSON.stringify(['t','second']);select.fire('change');
    assert.equal(document.getElementById('policy-allowed').value,'','identity change cannot inherit another identity policy');
    assert.doesNotMatch(content(), /legacy__missing/);
    click('MCP 服务');click('查看服务 · crm');
    assert.match(content(), /身份范围：t \/ second/);
    assert.match(content(), /无绑定记录/);
    assert.match(content(), /尚无发现目录/);
    // Managed lifecycle uses server-bound tickets, never the generic mutation endpoint.
    const managed={...snapshot,persistent:true,capabilities:{...snapshot.capabilities,user_create:true,entry_lifecycle:true}};
    elements.refresh.fire('click');await respond(managed);
    click('用户与入口 token');
    const fill=(id,value)=>{const e=document.getElementById(id);e.value=value;e.fire('input');};
    fill('new-tenant','tenant-new');fill('new-principal','principal-new');
    click('预览创建用户');
    assert.ok(calls.at(-1).url.endsWith('/lifecycle'));
    assert.deepEqual(JSON.parse(calls.at(-1).opts.body),{action:'create_user',tenant:'tenant-new',principal:'principal-new',expected_generation:0,preview:true});
    const ticket={preview:true,confirmation_id:'synthetic-ticket',confirmation_expires_at:'2099-01-01T00:00:00Z'};
    await respond(ticket);
    fill('new-principal','principal-edited');
    assert.equal(findButton('确认用户 / 入口变更'),undefined,'identity edits invalidate lifecycle tickets');
    lang('en');assert.equal(document.getElementById('new-principal').value,'principal-edited');lang('zh-CN');
    click('预览创建用户');await respond(ticket);
    click('确认用户 / 入口变更');
    const creation=JSON.parse(calls.at(-1).opts.body);
    assert.equal(creation.confirmation_id,'synthetic-ticket');assert.equal(creation.confirm,true);assert.equal(creation.preview,false);
    assert.equal(creation.allowed,undefined,'creation never grants tools');
    const newUser={tenant:'tenant-new',principal:'principal-edited',policy_version:1,allowed:[],disabled:false,entry:{generation:1,revoked:true},tools:[],bindings:[]};
    const created={...managed,users:[...managed.users,newUser]};
    await respond({applied:true,entry:newUser.entry});await respond(created);
    assert.equal(document.getElementById('identity-select').value,JSON.stringify(['tenant-new','principal-edited']));
    assert.ok(findButton('预览轮换入口 token').disabled);
    assert.equal(document.getElementById('entry-secret'),undefined);
    fill('entry-expiry','2099-12-31T23:59:59Z');
    click('预览颁发入口 token');const issueCount=calls.length;click('预览颁发入口 token');assert.equal(calls.length,issueCount);
    assert.equal(JSON.parse(calls.at(-1).opts.body).expected_generation,1);
    await respond(ticket);assert.match(content(),/2099.*UTC/);
    fill('entry-expiry','2098-12-31T23:59:59Z');assert.equal(findButton('确认用户 / 入口变更'),undefined);
    click('预览颁发入口 token');await respond(ticket);click('确认用户 / 入口变更');
    const issuedUser={...newUser,entry:{generation:2,revoked:false,expires_at:'2098-12-31T23:59:59Z'}};
    const issued={...created,users:[...managed.users,issuedUser]};
    await respond({applied:true,entry:issuedUser.entry,token:'synthetic-one-time-entry'});await respond(issued);
    assert.match(content(),/synthetic-one-time-entry/);assert.doesNotMatch(elements.message.textContent,/synthetic-one-time-entry/);
    assert.ok(findButton('预览颁发入口 token').disabled);
    lang('en');assert.match(content(),/synthetic-one-time-entry/);lang('zh-CN');
    click('已妥善保存，清除显示');assert.doesNotMatch(content(),/synthetic-one-time-entry/);
    elements.refresh.fire('click');await respond(issued);assert.doesNotMatch(content(),/synthetic-one-time-entry/,'snapshot never retrieves secrets');
    fill('entry-expiry','2099-12-31T23:59:59Z');click('预览轮换入口 token');await respond(ticket);click('确认用户 / 入口变更');
    const conflictCount=calls.length;await respond({error:'version_conflict'},409);
    assert.equal(calls.length,conflictCount);assert.match(elements.message.textContent,/版本已变化/);
    assert.equal(findButton('确认用户 / 入口变更'),undefined);
    click('预览轮换入口 token');await respond(ticket);click('确认用户 / 入口变更');
    const unknownCount=calls.length;pending.shift().reject(new Error('synthetic network loss'));await tick();
    assert.equal(calls.length,unknownCount);assert.match(elements.message.textContent,/无法取回旧秘密/);
    assert.equal(findButton('确认用户 / 入口变更'),undefined);
    click('预览轮换入口 token');click('MCP 服务');click('用户与入口 token');await respond(ticket);
    assert.equal(findButton('确认用户 / 入口变更'),undefined,'late preview cannot cross navigation');
    fill('entry-expiry','2099-12-31T23:59:59Z');click('预览轮换入口 token');await respond(ticket);click('确认用户 / 入口变更');
    const late=pending.shift();let resolveSecret;
    late.resolve({ok:true,status:200,json:()=>new Promise(r=>resolveSecret=r)});await tick();
    click('MCP 服务');click('用户与入口 token');
    resolveSecret({applied:true,entry:issuedUser.entry,token:'synthetic-late-secret'});await tick();await respond(issued);
    assert.doesNotMatch(content(),/synthetic-late-secret/,'secret decoded after navigation is discarded');
    // Secret clearing is independent from snapshot refresh, identity selection and browser lifecycle.
    async function successfulRotation(secret, snapshotStatus=200) {
      fill('entry-expiry','2099-12-31T23:59:59Z');click('预览轮换入口 token');await respond(ticket);click('确认用户 / 入口变更');
      await respond({applied:true,entry:issuedUser.entry,token:secret});
      await respond(snapshotStatus===200?issued:{error:'state_unavailable'},snapshotStatus);
    }
    await successfulRotation('synthetic-refresh-failure',503);
    assert.match(content(),/synthetic-refresh-failure/,'known committed secret survives failed metadata refresh');
    assert.match(elements.message.textContent,/操作已提交，但状态刷新失败/);
    elements.refresh.fire('click');assert.doesNotMatch(content(),/synthetic-refresh-failure/);await respond(issued);
    await successfulRotation('synthetic-selection-secret');
    const picker=document.getElementById('identity-select');picker.value=JSON.stringify(['t','<script>identity</script>']);picker.fire('change');
    assert.doesNotMatch(content(),/synthetic-selection-secret/);
    const back=document.getElementById('identity-select');back.value=JSON.stringify(['tenant-new','principal-edited']);back.fire('change');
    assert.doesNotMatch(content(),/synthetic-selection-secret/);
    await successfulRotation('synthetic-pagehide-secret');context.window.handlers.pagehide();
    assert.doesNotMatch(content(),/synthetic-pagehide-secret/);assert.equal(elements.authentication.hidden,false);
    await login();elements.refresh.fire('click');await respond(issued);click('用户与入口 token');
    const resumed=document.getElementById('identity-select');resumed.value=JSON.stringify(['tenant-new','principal-edited']);resumed.fire('change');
    fill('entry-expiry','2099-12-31T23:59:59Z');click('预览轮换入口 token');await respond(ticket);click('确认用户 / 入口变更');
    elements.disconnect.fire('click');await respond({applied:true,entry:issuedUser.entry,token:'synthetic-disconnected-secret'});
    assert.doesNotMatch(content(),/synthetic-disconnected-secret/);assert.equal(pending.length,0,'disconnected mutation does not fetch snapshot');
    await login();elements.refresh.fire('click');await respond(issued);click('用户与入口 token');
    const again=document.getElementById('identity-select');again.value=JSON.stringify(['tenant-new','principal-edited']);again.fire('change');
    click('预览撤销入口 token');
    assert.equal(JSON.parse(calls.at(-1).opts.body).expires_at,undefined);
    await respond(ticket);click('取消入口变更');assert.equal(findButton('确认用户 / 入口变更'),undefined);
    fill('entry-expiry','2099-12-31T23:59:59Z');click('预览轮换入口 token');await respond(ticket);click('确认用户 / 入口变更');
    await respond({applied:true,entry:issuedUser.entry,token:'synthetic-cleared-on-offline'});await respond(issued);
    assert.match(content(),/synthetic-cleared-on-offline/);context.window.handlers.offline();
    assert.doesNotMatch(content(),/synthetic-cleared-on-offline/);assert.equal(elements.authentication.hidden,false);
    await login();elements.refresh.fire('click');await respond({...managed,users:[]});click('用户与入口 token');
    assert.ok(!findButton('预览创建用户').disabled,'empty users can create first user');
    elements.refresh.fire('click');await respond({...managed,users:[{...issuedUser,disabled:true}]});
    assert.ok(findButton('预览颁发入口 token').disabled);assert.ok(findButton('预览轮换入口 token').disabled);assert.ok(findButton('预览撤销入口 token').disabled);
    elements.refresh.fire('click');await respond({...managed,capabilities:{}});
    assert.ok(findButton('预览创建用户').disabled);assert.ok(findButton('预览轮换入口 token').disabled);
    assert.ok(calls.every(c=>!c.opts.body?.includes('synthetic-one-time-entry')&&!c.opts.body?.includes('synthetic-late-secret')),'returned gateway secrets never enter requests');
    // Real service application is separate from static validation and uses the running registry.
    elements.refresh.fire('click');await respond(managed);click('配置与维护');
    assert.ok(findButton('预览服务配置应用').disabled);
    const runningSystems=[{name:'crm',endpoint:'https://example.test/mcp',auth:{mode:'bearer'},timeouts:{call_ms:2345}}];
    const registry={revision:4,digest:'synthetic-running-digest',systems:runningSystems,persistent:true,apply_supported:true,supported_changes:['add','timeouts']};
    click('读取运行配置并重置草稿');assert.ok(calls.at(-1).url.endsWith('/config/current'));await respond(registry);
    assert.deepEqual(JSON.parse(document.getElementById('config-draft').value),runningSystems);
    assert.match(content(),/启动 seed JSON/);assert.match(content(),/运行配置副本/);
    fill('draft-name','docs');fill('draft-endpoint','https://docs.example.test/mcp');click('加入本地草稿');
    const candidate=JSON.parse(document.getElementById('config-draft').value);
    click('预览服务配置应用');const configCount=calls.length;click('预览服务配置应用');assert.equal(calls.length,configCount);
    assert.deepEqual(JSON.parse(calls.at(-1).opts.body),{expected_revision:4,systems:candidate});
    const configTicket={preview:true,revision:4,candidate_digest:'synthetic-candidate-digest',confirmation_id:'synthetic-config-ticket',confirmation_expires_at:'2099-01-01T00:00:00Z',added:['docs'],updated:[],applied:false};
    await respond(configTicket);assert.match(content(),/新增服务：docs/);
    fill('config-draft',JSON.stringify(candidate));assert.match(content(),/生成并校验配置草稿 · 未应用/);assert.equal(findButton('确认应用服务配置'),undefined,'draft edits invalidate config ticket');
    click('预览服务配置应用');await respond(configTicket);lang('en');assert.ok(findButton('Confirm service configuration apply'));lang('zh-CN');
    click('取消配置应用');assert.equal(findButton('确认应用服务配置'),undefined);
    click('预览服务配置应用');await respond(configTicket);click('确认应用服务配置');
    assert.deepEqual(JSON.parse(calls.at(-1).opts.body),{expected_revision:4,systems:candidate,candidate_digest:'synthetic-candidate-digest',confirmation_id:'synthetic-config-ticket'});
    const appliedRegistry={applied:true,revision:5,digest:'synthetic-candidate-digest',systems:candidate,persistent:true,discovery_required:['docs']};
    await respond(appliedRegistry);await respond({...managed,services:candidate});
    assert.match(elements.message.textContent,/服务配置已应用/);assert.match(elements.message.textContent,/尚未验证连通性/);
    assert.match(content(),/运行配置副本/);assert.match(content(),/运行版本：5/);assert.equal(findButton('确认应用服务配置'),undefined);
    click('预览服务配置应用');await respond({...configTicket,revision:5});click('确认应用服务配置');
    const configConflictCount=calls.length;await respond({error:'version_conflict'},409);
    assert.equal(calls.length,configConflictCount);assert.ok(findButton('预览服务配置应用').disabled);assert.match(elements.message.textContent,/核对运行版本与摘要/);
    click('核对运行版本与摘要');await respond({...registry,...appliedRegistry});
    click('预览服务配置应用');await respond({...configTicket,revision:5});click('确认应用服务配置');
    const configUnknownCount=calls.length;pending.shift().reject(new Error('synthetic apply response loss'));await tick();
    assert.equal(calls.length,configUnknownCount);assert.match(elements.message.textContent,/配置应用结果未知/);assert.ok(findButton('预览服务配置应用').disabled);
    click('核对运行版本与摘要');await respond({...registry,...appliedRegistry});
    assert.match(elements.message.textContent,/摘要与目标一致/);assert.ok(!findButton('预览服务配置应用').disabled);
    click('预览服务配置应用');await respond({error:'unsupported_destructive_change'},400);
    assert.match(elements.message.textContent,/不能删除服务/);assert.equal(findButton('确认应用服务配置'),undefined);
    click('预览服务配置应用');click('MCP 服务');click('配置与维护');await respond(configTicket);
    assert.equal(findButton('确认应用服务配置'),undefined,'late config preview cannot cross page navigation');
    click('预览服务配置应用');await respond(configTicket);click('确认应用服务配置');await respond(appliedRegistry);await respond({error:'state_unavailable'},503);
    assert.match(elements.message.textContent,/已应用，但状态刷新失败/);assert.equal(findButton('确认应用服务配置'),undefined);
    click('核对运行版本与摘要');await respond({...registry,apply_supported:false});assert.ok(findButton('预览服务配置应用').disabled);
    click('核对运行版本与摘要');elements.disconnect.fire('click');await respond(registry);
    assert.equal(elements.authentication.hidden,false,'late registry cannot reconnect');
    assert.doesNotMatch(src,
      /localStorage|sessionStorage|innerHTML|insertAdjacentHTML|eval\(/);
    assert.ok(calls.every(c=>!c.url.includes('?')&&c.opts.credentials==='omit'&&c.opts.redirect==='error'));
    console.log('PASS admin frontend: service current/preview/apply CAS tickets, draft invalidation, unknown apply digest reconciliation, destructive rejection, committed-refresh failure and disabled mode; managed user creation without grants, lifecycle preview tickets, UTC expiry, one-time secret clearing, late secret/navigation isolation, network uncertainty, no retry, capability/disabled gating; scoped service overview/detail, grouped search/checkboxes, missing grant retention and removal, policy diff/preview invalidation, UTC time, empty/three-service states, timeouts draft preservation, initial state, memory-only auth, locales/drafts, duplicate prevention, safe text, capabilities, two-step CAS, 409/503, config not-applied, audit empty state, stale response and JSON-decode disconnect. Synthetic DOM only.');
})().catch(e=> {
    console.error(e);
    process.exitCode=1
});

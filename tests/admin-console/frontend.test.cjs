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
    addEventListener() {
    }
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
    assert.doesNotMatch(src,
      /localStorage|sessionStorage|innerHTML|insertAdjacentHTML|eval\(/);
    assert.ok(calls.every(c=>!c.url.includes('?')&&c.opts.credentials==='omit'&&c.opts.redirect==='error'));
    console.log('PASS admin frontend: scoped service overview/detail, grouped search/checkboxes, missing grant retention and removal, policy diff/preview invalidation, UTC time, empty/three-service states, timeouts draft preservation, initial state, memory-only auth, locales/drafts, duplicate prevention, safe text, capabilities, two-step CAS, 409/503, config not-applied, audit empty state, stale response and JSON-decode disconnect. Synthetic DOM only.');
})().catch(e=> {
    console.error(e);
    process.exitCode=1
});

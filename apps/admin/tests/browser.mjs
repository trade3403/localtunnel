import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { randomBytes } from 'node:crypto'
import { chromium } from 'playwright'
import http from 'node:http'
const exe=resolve(process.argv[2])
const evidence=resolve(process.argv[3])
const root=await mkdtemp(join(tmpdir(),'localtunnel-admin-'))
const password=randomBytes(24).toString('hex')
let server,frontend,browser,fixture,nginx,worker
let apiPort, page
let runtimePath, requestId, adminBearer
let fixtureInfo
let stage='initialize'
const report={}
const wait=ms=>new Promise(r=>setTimeout(r,ms))
async function close(p){
  if(!p||p.exitCode!==null)return
  p.kill('SIGTERM')
  for(let i=0;i<50&&p.exitCode===null;i++)await wait(100)
  if(p.exitCode===null)p.kill('SIGKILL')
}
try{
  assert.equal(spawnSync(exe,['--init-admin',root],{input:JSON.stringify({username:'operator',password}),timeout:20000}).status,0)
  const node=spawnSync(exe,['--add-node',root,'Local relay'],{timeout:20000,encoding:'utf8'})
  assert.equal(node.status,0)
  const localNode=node.stdout.trim()
  assert.match(localNode,/^[a-f0-9]{32}$/)
  assert.equal(spawnSync(exe,['--set-node-policy',root,localNode,'1','12','test-east','active'],{timeout:20000}).status,0)
  // Real SQLite fixtures to exercise server cursor boundaries without
  // manufacturing fake HTTP responses. The real CLI-created node sorts first.
  const seed=spawnSync('python3',['-c',`import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
    db.executemany("INSERT INTO nodes(id,name) VALUES (?,?)",[(f'z{i:03d}',f'Pagination fixture {i:03d}') for i in range(101)])
`,join(root,'control.sqlite3')],{timeout:20000})
  assert.equal(seed.status,0)
  fixture=spawn('python3',['tests/runtime_fixture.py',root],{stdio:['pipe','pipe','ignore']})
  fixtureInfo=await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('runtime fixture startup timeout')),120000)
    let buffer=''
    fixture.stdout.on('data',b=>{
      buffer+=b
      const i=buffer.indexOf('\n')
      if(i>=0){clearTimeout(timer);try{resolve(JSON.parse(buffer.slice(0,i)))}catch{reject(new Error('invalid fixture output'))}}
    })
    fixture.once('exit',()=>{clearTimeout(timer);reject(new Error('runtime fixture exited'))})
  })
  server=spawn(exe,[root,'0'],{stdio:['ignore','pipe','ignore'],env:{...process.env,LOCALTUNNEL_DNS_RESOLVER:fixtureInfo.dns}})
  apiPort=await new Promise((resolve,reject)=>{
    const t=setTimeout(()=>reject(new Error('server startup timeout')),20000)
    let buffer=''
    server.stdout.on('data',b=>{buffer+=b;const m=buffer.match(/LISTENING 127\.0\.0\.1:(\d+)/);if(m){clearTimeout(t);resolve(m[1])}})
    server.once('exit',()=>{clearTimeout(t);reject(new Error('server exited'))})
  })
  frontend=spawn(process.execPath,['node_modules/vite/bin/vite.js','preview','--host','127.0.0.1','--port','1430','--strictPort'],{env:{...process.env,LOCALTUNNEL_API_PORT:apiPort},stdio:'ignore'})
  for(let i=0;i<100;i++){
    if(frontend.exitCode!==null)throw new Error('frontend exited')
    try{if((await fetch('http://127.0.0.1:1430/')).ok)break}catch{}
    if(i===99)throw new Error('frontend timeout')
    await wait(100)
  }
  browser=await chromium.launch({headless:true})
  page=await browser.newPage({viewport:{width:1440,height:900}})
  const pageErrors=[]
  page.on('pageerror',e=>pageErrors.push(e.message))
  stage='login'
  await page.goto('http://127.0.0.1:1430/')
  await page.locator('#username').fill('operator')
  await page.locator('#password').fill('wrong-password-123')
  await page.getByRole('button',{name:'登录',exact:true}).click()
  await page.getByText('登录失败或会话已过期',{exact:true}).waitFor()
  await page.locator('#password').fill(password)
  await page.getByRole('button',{name:'登录',exact:true}).click()
  await page.getByRole('heading',{name:'仪表盘'}).waitFor()
  await page.locator('button:not(.ant-btn-loading)').filter({hasText:'刷新数据'}).waitFor()
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0)
  report.real_login_and_memory_session=true
  stage='nodes and devices'
  const menu=name=>page.getByRole('menuitem',{name,exact:true})
  await menu('节点管理').click()
  await page.getByText('Local relay',{exact:true}).waitFor()
  const nodeRow=page.getByTestId('node-overview').getByRole('row').filter({hasText:'Local relay'})
  await nodeRow.getByText('未注册',{exact:true}).waitFor()
  await nodeRow.getByText('test-east',{exact:true}).waitFor()
  await nodeRow.getByText('接收调度',{exact:true}).waitFor()
  await nodeRow.getByText('12 / —',{exact:true}).waitFor()
  await nodeRow.getByText('0 / 0',{exact:true}).waitFor()
  assert.equal(spawnSync(exe,['--set-node-policy',root,localNode,'2','9','test-west','active'],{timeout:20000}).status,0)
  await page.getByRole('button',{name:'刷新数据'}).click()
  await nodeRow.getByText('test-west',{exact:true}).waitFor()
  await nodeRow.getByText('9 / —',{exact:true}).waitFor()
  await page.getByTestId('nodes-count').filter({hasText:/^已加载 100 条$/}).waitFor()
  await page.getByTestId('nodes-more').click()
  await page.getByTestId('nodes-count').filter({hasText:/^已加载 102 条$/}).waitFor()
  await page.getByTestId('nodes-more').waitFor({state:'hidden'})
  report.real_cursor_pagination=true
  report.real_browser_node_overview_and_refresh=true
  await menu('设备管理').click()
  await page.getByRole('button',{name:'生成配对码'}).click()
  const code=await page.getByTestId('pairing').textContent()
  assert.match(code,/^ltpair_[a-f0-9]{64}$/)
  const enrolled=await fetch('http://127.0.0.1:'+apiPort+'/api/v1/devices/enroll',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pairing_code:code,name:'Browser fixture'})})
  assert.equal(enrolled.status,201)
  await enrolled.json()
  await page.getByRole('button',{name:'刷新数据'}).click()
  await page.getByText('Browser fixture',{exact:true}).waitFor()
  await page.getByRole('button',{name:'管理状态'}).click()
  await page.getByText('管理在线：否',{exact:true}).waitFor()
  stage='domains'
  await menu('域名管理').click()
  await page.getByRole('textbox',{name:'域名'}).fill('browser.example.test')
  await page.getByRole('button',{name:'添加域名'}).click()
  await page.getByText('browser.example.test',{exact:true}).waitFor()
  await page.getByText('未验证',{exact:true}).waitFor()
  report.real_node_device_pairing_domain=true
  stage='mapping controls'
  await menu('映射管理').click()
  // Actual Ant Design Vue select controls and the visible popup option.
  // Stable root identifiers are independent of how rc-select forwards ARIA.
  for(const [id,option] of [['mapping-device','Browser fixture'],['mapping-node','Local relay'],['mapping-domain','browser.example.test']]){
    await page.getByTestId(id).click()
    await page.locator('.ant-select-dropdown:visible').getByText(option,{exact:true}).click()
  }
  await page.getByRole('button',{name:'创建草稿'}).click()
  await page.getByRole('button',{name:'运行详情'}).click()
  await page.getByTestId('runtime-state').filter({hasText:/^尚无请求$/}).waitFor()
  await page.getByRole('button',{name:'请求启动'}).click()
  await page.getByText('状态冲突，请刷新并检查版本、域名验证或执行器状态',{exact:true}).waitFor()
  report.real_mapping_and_unverified_activation_denied=true
  stage='edit and delete'
  await page.getByRole('button',{name:'编辑映射',exact:true}).click()
  await page.locator('#edit-local-port').fill('8181')
  await page.getByRole('button',{name:'保存端口',exact:true}).click()
  await page.getByText('映射已更新',{exact:true}).waitFor()
  await page.getByRole('cell',{name:'8181',exact:true}).waitFor()
  await page.getByRole('cell',{name:'2',exact:true}).waitFor()
  await menu('域名管理').click()
  await page.getByRole('button',{name:'删除域名',exact:true}).click()
  await page.locator('.ant-popover:visible').getByRole('button',{name:'确认删除',exact:true}).click()
  await page.getByText('状态冲突，请刷新并检查版本、域名验证或执行器状态',{exact:true}).waitFor()
  await menu('映射管理').click()
  await page.getByRole('button',{name:'删除映射',exact:true}).click()
  await page.locator('.ant-popover:visible').getByRole('button',{name:'确认删除',exact:true}).click()
  await page.getByText('映射已删除',{exact:true}).waitFor()
  await page.getByRole('button',{name:'运行详情'}).waitFor({state:'hidden'})
  await menu('域名管理').click()
  await page.getByRole('button',{name:'删除域名',exact:true}).click()
  await page.locator('.ant-popover:visible').getByRole('button',{name:'确认删除',exact:true}).click()
  await page.getByText('域名已删除',{exact:true}).waitFor()
  await page.getByRole('cell',{name:'browser.example.test',exact:true}).waitFor({state:'hidden'})
  report.real_edit_delete_and_domain_reference_guard=true
  stage='UDP desired draft form'
  await menu('映射管理').click()
  for(const [id,option] of [['mapping-device','Browser fixture'],['mapping-node','Local relay'],['mapping-protocol','UDP']]){
    await page.getByTestId(id).click()
    await page.locator('.ant-select-dropdown:visible').getByText(option,{exact:true}).click()
  }
  await page.getByTestId('mapping-domain').waitFor({state:'hidden'})
  const udpCreated=page.waitForResponse(r=>r.url().endsWith('/api/v1/mappings')&&r.request().method()==='POST'&&r.status()===201)
  await page.getByRole('button',{name:'创建草稿'}).click()
  const udp=await (await udpCreated).json()
  assert.equal(udp.protocol,'udp')
  assert.equal(udp.domain_id,null)
  assert.equal(udp.enabled,false)
  await page.getByRole('button',{name:'运行详情'}).click()
  await page.getByText('UDP 仅限可信操作员预配置的本机回显预览；请求启动不代表实际运行或公网可达。',{exact:true}).waitFor()
  // The card and its static UDP hint render before the real runtime and
  // traffic requests finish. Wait for the actual settled state and enabled
  // control, not just the card's presence. Keep the original assertion.
  await page.getByTestId('runtime-state').filter({hasText:/^尚无请求$/}).waitFor({timeout:10000})
  const udpStartButton=page.getByRole('button',{name:'请求启动',exact:true})
  await udpStartButton.and(page.locator('button:enabled')).waitFor({timeout:10000})
  assert.equal(await udpStartButton.isDisabled(),false)
  const udpPath='/api/v1/mappings/'+udp.id
  const udpStarted=page.waitForResponse(r=>r.url().endsWith(udpPath+'/udp-start')&&r.status()===202)
  await page.getByRole('button',{name:'请求启动'}).click()
  const udpRequest=await (await udpStarted).json()
  assert.equal(udpRequest.state,'queued')
  await page.getByTestId('runtime-state').filter({hasText:/^等待执行器$/}).waitFor()
  // Enabled stop control proves the mutation's busy state has cleared;
  // the start button must still be disabled by the queued request itself.
  await page.getByRole('button',{name:'请求停止',exact:true}).and(page.locator('button:enabled')).waitFor({timeout:10000})
  assert.equal(await udpStartButton.isDisabled(),true)
  const udpStopped=page.waitForResponse(r=>r.url().endsWith(udpPath+'/stop')&&r.status()===202)
  await page.getByRole('button',{name:'请求停止'}).click()
  assert.equal((await (await udpStopped).json()).state,'stopped')
  await page.getByTestId('runtime-state').filter({hasText:/^已停止$/}).waitFor()
  await udpStartButton.and(page.locator('button:enabled')).waitFor({timeout:10000})
  assert.equal(await udpStartButton.isDisabled(),false)
  report.real_browser_udp_request_and_cancel=true
  await page.getByRole('button',{name:'删除映射',exact:true}).click()
  await page.locator('.ant-popover:visible').getByRole('button',{name:'确认删除',exact:true}).click()
  await page.getByText('映射已删除',{exact:true}).waitFor()
  await page.getByRole('button',{name:'运行详情'}).waitFor({state:'hidden'})
  stage='TCP desired draft form'
  await page.getByTestId('mapping-protocol').click()
  await page.locator('.ant-select-dropdown:visible').getByText('TCP',{exact:true}).click()
  await page.getByTestId('mapping-domain').waitFor({state:'hidden'})
  const tcpCreated=page.waitForResponse(r=>r.url().endsWith('/api/v1/mappings')&&r.request().method()==='POST'&&r.status()===201)
  await page.getByRole('button',{name:'创建草稿'}).click()
  const tcp=await (await tcpCreated).json()
  assert.equal(tcp.protocol,'tcp')
  assert.equal(tcp.domain_id,null)
  await page.getByRole('button',{name:'运行详情'}).click()
  await page.getByText('TCP 仅限可信操作员预配置的本机回显预览；请求启动不代表实际运行或公网可达。',{exact:true}).waitFor()
  await page.getByTestId('runtime-state').filter({hasText:/^尚无请求$/}).waitFor()
  const tcpStart=page.getByRole('button',{name:'请求启动',exact:true})
  await tcpStart.and(page.locator('button:enabled')).waitFor({timeout:10000})
  const tcpStarted=page.waitForResponse(r=>r.url().endsWith('/api/v1/mappings/'+tcp.id+'/tcp-start')&&r.status()===202)
  await tcpStart.click()
  assert.equal((await (await tcpStarted).json()).state,'queued')
  await page.getByTestId('runtime-state').filter({hasText:/^等待执行器$/}).waitFor()
  await page.getByRole('button',{name:'请求停止',exact:true}).and(page.locator('button:enabled')).waitFor({timeout:10000})
  assert.equal(await tcpStart.isDisabled(),true)
  const tcpStopped=page.waitForResponse(r=>r.url().endsWith('/api/v1/mappings/'+tcp.id+'/stop')&&r.status()===202)
  await page.getByRole('button',{name:'请求停止'}).click()
  assert.equal((await (await tcpStopped).json()).state,'stopped')
  await page.getByTestId('runtime-state').filter({hasText:/^已停止$/}).waitFor()
  await tcpStart.and(page.locator('button:enabled')).waitFor({timeout:10000})
  report.real_browser_tcp_request_and_cancel=true
  await page.getByRole('button',{name:'删除映射',exact:true}).click()
  await page.locator('.ant-popover:visible').getByRole('button',{name:'确认删除',exact:true}).click()
  await page.getByText('映射已删除',{exact:true}).waitFor()
  await page.getByRole('button',{name:'运行详情'}).waitFor({state:'hidden'})
  await menu('域名管理').click()
  await menu('映射管理').click()
  await page.getByTestId('mapping-protocol').click()
  await page.locator('.ant-select-dropdown:visible').getByText('HTTP',{exact:true}).click()
  await menu('域名管理').click()
  stage='real browser worker lifecycle'
  // Create a new domain through the actual UI, extract only its public TXT
  // challenge from the actual HTTP response, and answer via real TCP DNS.
  const domainCreated=page.waitForResponse(r=>r.url().endsWith('/api/v1/domains')&&r.request().method()==='POST'&&r.status()===201)
  await page.getByRole('textbox',{name:'域名'}).fill('runtime.example.test')
  await page.getByRole('button',{name:'添加域名'}).click()
  const domain=await (await domainCreated).json()
  await writeFile(join(root,'dns_record.json'),JSON.stringify({name:domain.txt_name,value:domain.txt_value}),{mode:0o600})
  await page.getByRole('cell',{name:'runtime.example.test',exact:true}).waitFor()
  await page.getByRole('button',{name:/验\s*证/}).click()
  await page.getByText('DNS TXT 验证成功',{exact:true}).waitFor()
  await menu('映射管理').click()
  for(const [id,option] of [['mapping-device','Browser fixture'],['mapping-node','Local relay'],['mapping-domain','runtime.example.test']]){
    await page.getByTestId(id).click()
    await page.locator('.ant-select-dropdown:visible').getByText(option,{exact:true}).click()
  }
  // Fill the existing real form and capture the actual created mapping ID.
  await page.locator('.mapping-form input[role="spinbutton"]').first().fill(String(fixtureInfo.local))
  const mappingCreated=page.waitForResponse(r=>r.url().endsWith('/api/v1/mappings')&&r.request().method()==='POST'&&r.status()===201)
  await page.getByRole('button',{name:'创建草稿'}).click()
  const mapping=await (await mappingCreated).json()
  assert.equal(mapping.local_port,fixtureInfo.local)
  const {mkdir}=await import('node:fs/promises')
  await mkdir(join(root,'browser_gateway'),{mode:0o700})
  const env={...process.env,LOCALTUNNEL_CORE_CLI:fixtureInfo.core,LOCALTUNNEL_ENGINE:fixtureInfo.engine,LOCALTUNNEL_SERVER_PRIVATE_KEY:fixtureInfo.private,LOCALTUNNEL_SERVER_PUBLIC_KEY:fixtureInfo.public}
  const prefix=join(root,'browser_gateway')
  assert.equal(spawnSync(exe,['--preview-gateway',root,'clear','0','browser_gateway',String(fixtureInfo.gateway),'init'],{env,timeout:20000,stdio:'ignore'}).status,0)
  nginx=spawn('/usr/sbin/nginx',['-p',prefix+'/','-c',join(prefix,'nginx.conf'),'-g','daemon off;'],{stdio:'ignore'})
  const gatewayUrl='http://127.0.0.1:'+fixtureInfo.gateway+'/'
  const probe=url=>new Promise(resolve=>{
    const req=http.get(url,{headers:{Host:'runtime.example.test',Connection:'close'},timeout:2000},r=>{
      let body='';r.setEncoding('utf8');r.on('data',b=>body+=b);r.on('end',()=>resolve([r.statusCode,body]));r.on('error',()=>resolve(null))
    })
    req.on('timeout',()=>req.destroy());req.on('error',()=>resolve(null))
  })
  async function until(fn,description,ms=45000){
    const end=Date.now()+ms
    while(Date.now()<end){if(await fn())return;await wait(250)}
    throw new Error(description)
  }
  await until(async()=>(await probe(gatewayUrl))?.[0]===421,'empty browser gateway unavailable')
  await page.getByRole('button',{name:'运行详情'}).click()
  await page.getByTestId('runtime-state').filter({hasText:/^尚无请求$/}).waitFor()
  runtimePath='/api/v1/mappings/'+mapping.id
  const started=page.waitForResponse(r=>r.url().endsWith(runtimePath+'/start')&&r.status()===202)
  await page.getByRole('button',{name:'请求启动'}).click()
  const startResponse=await started
  adminBearer=await startResponse.request().headerValue('authorization')
  requestId=(await startResponse.json()).request_id
  await page.getByTestId('runtime-state').filter({hasText:/^等待执行器$/}).waitFor()
  assert.equal((await probe(gatewayUrl))[0],421)
  worker=spawn(exe,['--runtime-worker',root,mapping.id,String(mapping.revision),String(fixtureInfo.relay),'browser_bundle','browser_gateway',String(fixtureInfo.gateway),'expected_body'],{env,stdio:'ignore'})
  await until(async()=>{
    assert.equal(worker.exitCode,null,'browser runtime worker exited')
    const r=await probe(gatewayUrl)
    return r?.[0]===200&&r[1]===fixtureInfo.body
  },'real browser requested HTTP traffic never converged')
  await until(async()=>{
    await page.getByRole('button',{name:'刷新状态'}).click()
    await page.locator('button:not(.ant-btn-loading)').filter({hasText:'刷新数据'}).waitFor()
    // Clicking refresh is real API traffic; wait for actual reported phase.
    try{await page.getByTestId('runtime-state').filter({hasText:'已应用（执行器报告）'}).waitFor({timeout:1000});return true}catch{return false}
  },'worker state never displayed')
  for(let i=0;i<3;i++)assert.deepEqual(await probe(gatewayUrl),[200,fixtureInfo.body])
  await until(async()=>{
    const response=page.waitForResponse(r=>r.url().endsWith(runtimePath+'/traffic')&&r.status()===200)
    await page.getByRole('button',{name:'刷新状态'}).click()
    const usage=await (await response).json()
    const observation=usage.observations.find(x=>x.request_id===requestId)
    return observation&&observation.requests>=3&&observation.request_bytes>0&&observation.response_bytes>=3*fixtureInfo.body.length
  },'real gateway traffic counters never reached browser')
  await page.getByTestId('traffic-table').waitFor()
  report.real_gateway_traffic_visible_in_browser=true
  await page.getByRole('button',{name:'请求停止'}).click()
  await until(async()=>worker.exitCode!==null,'browser requested stop did not complete')
  assert.equal(worker.exitCode,0)
  await page.getByRole('button',{name:'刷新状态'}).click()
  await page.getByTestId('runtime-state').filter({hasText:/^已停止$/}).waitFor()
  assert.equal((await probe(gatewayUrl))[0],421)
  assert.equal(await probe('http://127.0.0.1:'+mapping.bind_port+'/'),null)
  report.real_browser_start_stop_noise_gateway=true
  stage='committed audit'
  await menu('操作审计').click()
  await page.getByTestId('audit-table').getByText('执行状态变更',{exact:true}).first().waitFor()
  await page.getByTestId('audit-table').getByRole('cell',{name:'stopped',exact:true}).first().waitFor()
  const audit=await fetch('http://127.0.0.1:'+apiPort+'/api/v1/audit',{headers:{Authorization:adminBearer}})
  assert.equal(audit.status,200)
  const history=await audit.json()
  const transitions=history.events.filter(x=>x.request_id===requestId).map(x=>x.state)
  assert.deepEqual(transitions,['stopped','stopping','running','starting','queued'])
  assert.ok(history.events.some(x=>x.event==='mapping.deleted'))
  assert.ok(history.events.some(x=>x.event==='domain.deleted'))
  report.real_committed_audit_visible_in_browser=true
  stage='commercial owner inventory'
  const cli=(action,input)=>{
    const result=spawnSync(exe,[action,root],{input:JSON.stringify(input),encoding:'utf8',timeout:20000})
    assert.equal(result.status,0,'commercial CLI failed')
    return result.stdout.trim()
  }
  const plan=cli('--commercial-create-plan',{code:'browser-quota',version:1,name:'Browser quota fixture',max_active_devices:3,max_retained_devices:5,max_mappings:7,max_bandwidth_bps:1048576,max_monthly_bytes:123456,max_concurrent_connections:4})
  const other=cli('--commercial-create-account',{username:'other-owner',password,plan_id:plan,expires_at:null})
  const entitlement=async()=>{
    const r=await fetch('http://127.0.0.1:'+apiPort+'/api/v1/commercial/entitlement',{headers:{Authorization:adminBearer}})
    assert.equal(r.status,200)
    return (await r.json()).entitlement
  }
  const own=await entitlement()
  assert.notEqual(own.tenant_id,other)
  const assign=(state,expires_at,revision)=>cli('--commercial-assign',{tenant_id:own.tenant_id,plan_id:plan,expected_revision:revision,state,expires_at})
  assign('active',null,own.revision)
  await menu('套餐与额度').click()
  const card=page.getByTestId('commercial-entitlement')
  const usage=page.getByTestId('commercial-usage')
  await card.getByText('Browser quota fixture',{exact:true}).waitFor()
  await card.getByText(own.tenant_id,{exact:true}).waitFor()
  assert.equal(await card.getByText(other,{exact:true}).count(),0)
  const active=await entitlement()
  assert.equal(active.plan_id,plan)
  assert.equal(active.active_devices,1)
  assert.equal(active.mappings,1)
  await usage.getByText('1 / 3',{exact:true}).waitFor()
  await usage.getByText('1 / 5',{exact:true}).waitFor()
  await usage.getByText('1 / 7',{exact:true}).waitFor()
  await usage.getByText('0 / 4',{exact:true}).waitFor()
  await usage.getByText('1,048,576',{exact:true}).waitFor()
  await usage.getByText(active.month_utc+'：0 / 123,456',{exact:true}).waitFor()
  assign('suspended',null,active.revision)
  await page.getByRole('button',{name:'刷新数据'}).click()
  await card.getByText('已暂停',{exact:true}).waitFor()
  const suspended=await entitlement()
  assign('active',Math.floor(Date.now()/1000)-60,suspended.revision)
  await page.getByRole('button',{name:'刷新数据'}).click()
  await card.getByText('已过期',{exact:true}).waitFor()
  report.real_browser_commercial_entitlement_and_refresh=true
  // Independent browser context and real second owner login.
  const otherPage=await browser.newPage()
  try{
    await otherPage.goto('http://127.0.0.1:1430/')
    await otherPage.locator('#username').fill('other-owner')
    await otherPage.locator('#password').fill(password)
    await otherPage.getByRole('button',{name:'登录',exact:true}).click()
    await otherPage.getByRole('menuitem',{name:'套餐与额度',exact:true}).click()
    const otherCard=otherPage.getByTestId('commercial-entitlement')
    await otherCard.getByText(other,{exact:true}).waitFor()
    await otherCard.getByText('有效',{exact:true}).waitFor()
    assert.equal(await otherCard.getByText(own.tenant_id,{exact:true}).count(),0)
    await otherPage.getByTestId('commercial-usage').getByText('0 / 3',{exact:true}).waitFor()
    await otherPage.getByTestId('commercial-usage').getByText('0 / 7',{exact:true}).waitFor()
    await otherPage.getByRole('button',{name:'退出登录'}).click()
    await otherCard.waitFor({state:'hidden'})
    assert.equal(await otherPage.evaluate(()=>localStorage.length+sessionStorage.length),0)
  }finally{await otherPage.close()}
  report.real_browser_commercial_owner_isolation=true
  stage='logout'
  await page.getByRole('button',{name:'退出登录'}).click()
  await page.getByRole('heading',{name:'管理后台登录'}).waitFor()
  assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0)
  assert.deepEqual(pageErrors,[])
  report.logout_no_browser_errors=true
}catch(e){
  // Print only the named test phase, not the DOM, request bodies, or secrets.
  console.error('Admin browser E2E failed at phase: '+stage)
  throw e
}finally{
  if(worker&&worker.exitCode===null&&runtimePath&&requestId&&adminBearer){
    try{
      await fetch('http://127.0.0.1:'+apiPort+runtimePath+'/stop',{method:'POST',headers:{Authorization:adminBearer,'Content-Type':'application/json'},body:JSON.stringify({request_id:requestId}),signal:AbortSignal.timeout(4000)})
      for(let i=0;i<400&&worker.exitCode===null;i++)await wait(100)
    }catch{}
  }
  await close(worker);await close(nginx)
  if(browser)await browser.close()
  await close(frontend);await close(server)
  if(fixture)fixture.stdin.end()
  await close(fixture)
  await rm(root,{recursive:true,force:true})
  await writeFile(evidence,JSON.stringify(report,null,2))
}

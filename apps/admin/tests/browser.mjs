import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { randomBytes } from 'node:crypto'
import { chromium } from 'playwright'
const exe=resolve(process.argv[2])
const evidence=resolve(process.argv[3])
const root=await mkdtemp(join(tmpdir(),'localtunnel-admin-'))
const password=randomBytes(24).toString('hex')
let server,frontend,browser
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
  server=spawn(exe,[root,'0'],{stdio:['ignore','pipe','ignore']})
  const apiPort=await new Promise((resolve,reject)=>{
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
  const page=await browser.newPage({viewport:{width:1440,height:900}})
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
  await menu('设备管理').click()
  await page.getByRole('button',{name:'生成配对码'}).click()
  const code=await page.getByTestId('pairing').textContent()
  assert.match(code,/^ltpair_[a-f0-9]{64}$/)
  const enrolled=await fetch('http://127.0.0.1:'+apiPort+'/api/v1/devices/enroll',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pairing_code:code,name:'Browser fixture'})})
  assert.equal(enrolled.status,201)
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
  if(browser)await browser.close()
  await close(frontend);await close(server)
  await rm(root,{recursive:true,force:true})
  await writeFile(evidence,JSON.stringify(report,null,2))
}

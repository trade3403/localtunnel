// Real installed WebView2 UI + Rust IPC + encrypted TCP. Node >=22.
// Test-only loopback CDP endpoint; never enable debugging in app config.
// No saved real credentials, screenshots, or payload logs.
import { spawn, execFileSync } from 'node:child_process'
import { createServer as tcpServer } from 'node:net'
import { createServer as httpServer } from 'node:http'
import { createSocket as udpSocket } from 'node:dgram'
import { randomBytes } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, rm, readFile, readdir } from 'node:fs/promises'
import { dirname, join, resolve, basename } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'

const [exeArg, evidenceArg] = process.argv.slice(2)
if (!exeArg || !evidenceArg || process.platform !== 'win32') throw Error('Windows installed GUI test arguments required')
if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted' || process.env.RUNNER_OS !== 'Windows') {
  throw Error('temporary CDP policy is restricted to disposable GitHub-hosted Windows runners')
}
const exe = resolve(exeArg)
const evidence = resolve(evidenceArg)
const engine = join(dirname(exe), 'engine', 'rathole.exe')
const work = await mkdtemp(join(tmpdir(), 'localtunnel-gui-'))
const report = { scope: 'installed WebView2 desktop and SCM DOM controls + real IPC + loopback encrypted HTTP + native WM_CLOSE + real shell-registered native tray popup menu input; not physical right-click on shell icon or public E2E',
  ui_ready: false, mapping_add_remove: false, port_probe: false,
  start_clicked: false, encrypted_http: false, traffic_visible: false,
  native_close_hides: false, hidden_tunnel_works: false, native_restore: false,
  stop_clicked: false, forwarding_stopped: false, history_visible: false }
let app, relay, socket, fixture, policy, alternate, management, udpFixture
let managementFile, managementCreated=false
let serviceName
report.service_provisioned = false
report.service_startup_controls = false
report.service_recovery_controls = false
report.service_real_http = false
report.service_traffic_visible = false
report.service_stopped = false
report.service_config_updated = false
report.service_updated_http = false
report.service_unregistered = false
report.service_data_preserved = false
report.tray_first_restore_clicked = false
report.tray_show_clicked = false
report.tray_second_hidden_http = false
report.tray_stop_clicked = false
report.tray_quit_clicked = false
report.tray_quit_clean_exit = false
report.tray_quit_forwarding_stopped = false
report.cdp_policy_created = false
report.cdp_policy_removed = false
report.cdp_http_reachable = false
report.cdp_target_types = []
// Runtime 150+ ignores browser-argument environment overrides for elevated
// hosts. GitHub-hosted Windows jobs are elevated. Use the supported per-app
// machine policy only during this disposable CI test, never in the installer.
// Upstream: https://github.com/tauri-apps/wry/issues/1782
function ps(script) {
  return execFileSync('powershell.exe', ['-NoProfile','-NonInteractive','-EncodedCommand',
    Buffer.from("$ErrorActionPreference='Stop';\r\n" + script,'utf16le').toString('base64')],
    { encoding:'utf8', timeout:15000, windowsHide:true }).trim()
}
function installDebugPolicy(port) {
  if (basename(exe).toLowerCase() !== 'localtunnel-desktop.exe' ||
      !Number.isInteger(port) || port < 1024 || port > 65535) throw Error('invalid temporary debug policy target')
  const value = '--remote-debugging-port=' + port + ' --remote-debugging-address=127.0.0.1'
  // Never overwrite an existing per-app policy, or change wildcard policies.
  ps([
    "$key='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\WebView2\\AdditionalBrowserArguments'",
    "$name='localtunnel-desktop.exe'",
    "if(!(Test-Path -LiteralPath $key)){New-Item -Path $key -Force | Out-Null}",
    "$item=Get-Item -LiteralPath $key",
    "if($item.GetValueNames() -contains $name){throw 'existing app policy; refusing overwrite'}",
    "if($item.GetValueNames() -contains '*'){throw 'existing wildcard policy; refusing modification'}",
    "New-ItemProperty -LiteralPath $key -Name $name -PropertyType String -Value '" + value + "' | Out-Null"
  ].join('\r\n'))
  policy = value
  report.cdp_policy_created = true
}
function removeDebugPolicy() {
  if (!policy) return
  ps([
    "$key='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge\\WebView2\\AdditionalBrowserArguments'",
    "$name='localtunnel-desktop.exe'",
    "$item=Get-Item -LiteralPath $key",
    "if($item.GetValue($name) -ne '" + policy + "'){throw 'temporary policy changed; refusing to delete another value'}",
    "Remove-ItemProperty -LiteralPath $key -Name $name",
    "if((Get-Item -LiteralPath $key).GetValueNames() -contains $name){throw 'temporary policy remains'}"
  ].join('\r\n'))
  policy = undefined
  report.cdp_policy_removed = true
}
const sleep = ms => new Promise(r => setTimeout(r, ms))
async function until(label, check, ms = 25000) {
  const end = Date.now() + ms
  while (Date.now() < end) {
    if (app && app.exitCode !== null) throw Error('installed GUI exited unexpectedly')
    if (relay && relay.exitCode !== null) throw Error('test relay exited unexpectedly')
    try { const value = await check(); if (value) return value } catch {}
    await sleep(250)
  }
  throw Error('GUI gate timed out: ' + label)
}
async function listen(server) {
  await new Promise((ok, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', ok) })
  return server.address().port
}
async function close(server) { if (server?.listening) await new Promise(ok => server.close(ok)) }
async function freePorts() {
  const servers = [tcpServer(), tcpServer(), tcpServer()]
  try {
    return await Promise.all(servers.map(listen))
  } finally { await Promise.all(servers.map(close)) }
}
async function terminate(child) {
  if (!child || child.exitCode !== null) return
  child.kill()
  await Promise.race([new Promise(ok => child.once('exit', ok)), sleep(5000)])
}
function launch(file, args, env = process.env) {
  const child = spawn(file, args, { env, stdio: 'ignore', windowsHide: false })
  child.on('error', () => {}) // bounded readiness checks report failure
  return child
}
let serial = 0
const pending = new Map()
async function connectCdp(port) {
  const endpoint = await until('WebView2 debug target', async () => {
    const response = await fetch('http://127.0.0.1:' + port + '/json/list', { signal: AbortSignal.timeout(2000) })
    if (!response.ok) return null
    report.cdp_http_reachable = true
    const list = await response.json()
    if (!Array.isArray(list)) return null
    report.cdp_target_types = [...new Set(list.map(t => t.type).filter(t => typeof t === 'string' && /^[a-zA-Z_]{1,32}$/.test(t)))].slice(0,16)
    return list.find(t => ['page','webview'].includes(t.type) && typeof t.webSocketDebuggerUrl === 'string' && /^https?:\/\/(tauri\.localhost|localhost)([:/]|$)/.test(t.url))?.webSocketDebuggerUrl
  }, 60000)
  const url = new URL(endpoint)
  if (!['127.0.0.1', 'localhost'].includes(url.hostname) || Number(url.port) !== port) throw Error('unexpected CDP endpoint')
  socket = new WebSocket(endpoint)
  await new Promise((ok, fail) => {
    const timer = setTimeout(() => fail(Error('CDP connection timeout')), 10000)
    socket.addEventListener('open', () => { clearTimeout(timer); ok() }, { once: true })
    socket.addEventListener('error', () => { clearTimeout(timer); fail(Error('CDP connection failed')) }, { once: true })
  })
  socket.addEventListener('message', event => {
    const msg = JSON.parse(event.data)
    const request = pending.get(msg.id)
    if (!request) return
    pending.delete(msg.id)
    clearTimeout(request.timer)
    if (msg.error) request.fail(Error('CDP protocol error'))
    else request.ok(msg.result)
  })
}
function cdp(method, params) {
  const id = ++serial
  return new Promise((ok, fail) => {
    const timer = setTimeout(() => { pending.delete(id); fail(Error('CDP command timeout')) }, 5000)
    pending.set(id, { ok, fail, timer })
    socket.send(JSON.stringify({ id, method, params }))
  })
}
async function evaluate(expression) {
  const result = await cdp('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  if (result.exceptionDetails) throw Error('WebView expression failed')
  return result.result?.value
}
const q = JSON.stringify
async function field(selector, value) {
  const success = await evaluate('(()=>{const e=document.querySelector(' + q(selector) + ');if(!e||e.disabled)return false;e.value=' + q(String(value)) + ';e.dispatchEvent(new Event("input",{bubbles:true}));e.dispatchEvent(new Event("change",{bubbles:true}));return true})()')
  if (!success) throw Error('form field unavailable: ' + selector)
}
async function click(text) {
  const success = await evaluate('(()=>{const b=[...document.querySelectorAll("button")].find(e=>e.textContent.trim()===' + q(text) + ');if(!b||b.disabled)return false;b.click();return true})()')
  if (!success) throw Error('button unavailable: ' + text)
}
async function serviceStat(label) {
  return evaluate('(()=>{const s=[...document.querySelectorAll("section")].find(e=>e.querySelector("h2")?.textContent==="Windows 后台服务");return [...(s?.querySelectorAll(".summary div")||[])].find(e=>e.querySelector("small")?.textContent===' + q(label) + ')?.querySelector("strong")?.textContent.trim()||null})()')
}
async function waitStat(label, value) {
  await until('service ' + label + ' = ' + value, async () => await serviceStat(label) === value, 35000)
}
async function waitButton(text) {
  await until('enabled service button ' + text, () => evaluate('[...document.querySelectorAll("button")].some(e=>!e.disabled&&e.textContent.trim()===' + q(text) + ')'), 35000)
}
async function serviceClick(text) {
  await waitButton(text)
  await click(text)
}
function servicePath(name) {
  if (!/^LocalTunnelPreview-[0-9a-f]{32}$/.test(name)) throw Error('invalid generated service name')
  if (!process.env.ProgramData) throw Error('ProgramData unavailable')
  return join(process.env.ProgramData,name)
}
function statusCli(name) {
  return JSON.parse(execFileSync(exe,['--service-status',name],{encoding:'utf8',timeout:15000,windowsHide:true}))
}
function scAbsent(name) {
  // The exact generated test service only. SCM error 1060 means nonexistent.
  try {
    execFileSync(join(process.env.SystemRoot,'System32','sc.exe'),['query',name],{encoding:'utf8',timeout:10000,windowsHide:true,stdio:'pipe'})
    return false
  } catch(e) { return e.status === 1060 || /1060/.test(String(e.stdout||'')) }
}
function cleanupTestService(name) {
  // Emergency cleanup only: no production services, no arbitrary paths.
  if (!/^LocalTunnelPreview-[0-9a-f]{32}$/.test(name)) return
  for (const args of [['--service-manage',name,'recovery-off'],['--service-manage',name,'stop'],['--service-unregister',name,name]]) {
    try { execFileSync(exe,args,{stdio:'ignore',timeout:35000,windowsHide:true}) } catch {}
  }
}
async function has(text) { return evaluate('document.body.innerText.includes(' + q(text) + ')') }
async function waitText(text) { await until(text, () => has(text)) }
async function get(url) {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(2000) })
    return r.ok ? await r.text() : null
  } catch { return null }
}
// Exact app HWND, native Win32 close/visibility; no global process action.
function windowAction(handle, action) {
  const script = [
    'Add-Type -TypeDefinition @\'',
    'using System; using System.Runtime.InteropServices;',
    'public static class GuiNative {',
    '[DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h,uint m,IntPtr w,IntPtr l);',
    '[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);',
    '[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);',
    '}',
    "'@",
    '$ProgressPreference="SilentlyContinue"; $h=[IntPtr]::new(' + handle + '); $owner=[uint32]0; [void][GuiNative]::GetWindowThreadProcessId($h,[ref]$owner);',
    'if($owner -ne ' + app.pid + '){throw "unexpected window owner"}',
    action === 'close' ? 'if(![GuiNative]::PostMessage($h,0x10,[IntPtr]::Zero,[IntPtr]::Zero)){throw "WM_CLOSE failed"}' :
      '[Console]::WriteLine([GuiNative]::IsWindowVisible($h))'
  ].join('\r\n')
  return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script,'utf16le').toString('base64')], { encoding: 'utf8', timeout: 10000, windowsHide:true }).trim()
}
function trayMenu(action) {
  const script = fileURLToPath(new URL('./native_tray_e2e.ps1',import.meta.url))
  try {
    execFileSync('pwsh.exe',['-NoProfile','-NonInteractive','-File',script,'-ProcessId',String(app.pid),'-Executable',exe,'-Action',action],
      {encoding:'utf8',timeout:40000,windowsHide:true,stdio:['ignore','pipe','pipe']})
  } catch (error) {
    // Only the native helper's diagnostic output, never CDP/form/fixture data.
    report.tray_failed_action = action
    report.tray_helper_error = String(error.stderr || error.code || 'native helper failed').slice(0,2000)
    console.error('Native tray helper failed (' + action + '): ' + report.tray_helper_error)
    throw Error('native tray menu action failed: ' + action)
  }
}
function windowHandle() {
  const result = execFileSync('powershell.exe', ['-NoProfile','-NonInteractive','-Command',
    '(Get-Process -Id ' + app.pid + ').MainWindowHandle.ToInt64()'], { encoding:'utf8', timeout:10000 }).trim()
  return /^\d+$/.test(result) && result !== '0' ? result : null
}
try {
  const body = randomBytes(48).toString('hex')
  fixture = httpServer((_req,res) => { res.writeHead(200, {'Content-Length': Buffer.byteLength(body)}); res.end(body) })
  const localPort = await listen(fixture)
  const [relayPort, mappedPort, debugPort] = await freePorts()
  const keys = execFileSync(engine, ['--genkey'], { encoding:'utf8', timeout:15000 })
  const privateKey = /Private Key:\s*([A-Za-z0-9+/=]+)/.exec(keys)?.[1]
  const publicKey = /Public Key:\s*([A-Za-z0-9+/=]+)/.exec(keys)?.[1]
  if (!privateKey || !publicKey) throw Error('test relay key generation failed')
  const token = randomBytes(32).toString('hex')
  const udpToken = randomBytes(32).toString('hex')
  const bindUdp = s => new Promise((ok,fail)=>{s.once('error',fail);s.bind(0,'127.0.0.1',()=>ok(s.address().port))})
  udpFixture=udpSocket('udp4')
  const udpLocal=await bindUdp(udpFixture)
  udpFixture.on('message',(data,peer)=>udpFixture.send(data,peer.port,peer.address))
  const reservation=udpSocket('udp4')
  const udpMapped=await bindUdp(reservation)
  await new Promise(ok=>reservation.close(ok))
  const config = join(work, 'server.toml')
  await writeFile(config, [
    '[server]', 'bind_addr = "127.0.0.1:' + relayPort + '"', 'heartbeat_interval = 5',
    '[server.transport]', 'type = "noise"', '[server.transport.noise]',
    'pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"', 'local_private_key = "' + privateKey + '"',
    '[server.services.web]', 'type = "tcp"', 'token = "' + token + '"',
    'bind_addr = "127.0.0.1:' + mappedPort + '"',
    '[server.services.udp_echo]', 'type = "udp"', 'token = "' + udpToken + '"',
    'bind_addr = "127.0.0.1:' + udpMapped + '"', ''
  ].join('\n'))
  relay = launch(engine, [config])
  installDebugPolicy(debugPort)
  app = launch(exe, [], { ...process.env, WEBVIEW2_USER_DATA_FOLDER: join(work,'webview') })
  await connectCdp(debugPort)
  await until('ready enabled input', () => evaluate('!!document.querySelector("input[placeholder=\\"relay.example.com:2333\\"]:not(:disabled)")'))
  report.ui_ready = true
  // Real management API built from this exact commit, never a mock.
  if (!process.env.LOCALTUNNEL_TEST_MANAGEMENT) throw Error('management test executable unavailable')
  const control=resolve(process.env.LOCALTUNNEL_TEST_MANAGEMENT)
  const data=join(work,'management')
  await mkdir(data)
  const password=randomBytes(24).toString('hex')
  execFileSync(control,['--init-admin',data],{input:JSON.stringify({username:'operator',password}),stdio:['pipe','ignore','ignore'],timeout:30000,windowsHide:true})
  const tempPort=tcpServer()
  const managementPort=await listen(tempPort);await close(tempPort)
  management=launch(control,[data,String(managementPort)])
  const base='http://127.0.0.1:'+managementPort
  await until('real management API ready',async()=>{try{return (await fetch(base+'/readyz',{signal:AbortSignal.timeout(1500)})).ok}catch{return false}},30000)
  async function manage(path,method='GET',bearer,body){
    const headers={}
    if(bearer)headers.Authorization='Bearer '+bearer
    if(body)headers['Content-Type']='application/json'
    return fetch(base+'/api/v1/'+path,{method,headers,body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(8000)})
  }
  const login=await manage('auth/login','POST',null,{username:'operator',password})
  if(login.status!==200)throw Error('management login failed')
  const admin=(await login.json()).access_token
  const pair=await manage('devices/pairing-code','POST',admin)
  if(pair.status!==200)throw Error('management pairing issue failed')
  const code=(await pair.json()).pairing_code
  managementFile=join(process.env.APPDATA,'com.localtunnel.desktop','management-device.bin')
  try{await readFile(managementFile);throw Error('existing management credentials: refusing to overwrite')}
  catch(e){if(e.code!=='ENOENT')throw e}
  managementCreated=true
  await field('input[aria-label="本机管理端口"]',managementPort)
  await field('input[aria-label="管理设备名称"]','Installed Windows fixture')
  await field('input[aria-label="管理配对码"]',code)
  await click('配对管理设备')
  await waitText('设备已配对，凭据已加密保存')
  const blob=await readFile(managementFile)
  if(!blob.length||blob.includes(Buffer.from('ltdev_'))||blob.includes(Buffer.from(code)))throw Error('management credential not protected')
  const listed=await manage('devices','GET',admin)
  const devices=await listed.json()
  if(listed.status!==200||devices.length!==1||devices[0].name!=='Installed Windows fixture')throw Error('real device enrollment missing')
  const device=devices[0]
  await click('同步管理状态')
  await waitText('配置元数据及管理心跳同步成功')
  const observed=await manage('devices/'+device.id+'/status','GET',admin)
  const heartbeat=await observed.json()
  if(observed.status!==200||!heartbeat.management_online||!heartbeat.configuration_current||heartbeat.reported_state!=='idle')throw Error('real desktop heartbeat missing')
  // Create real desired metadata after the manual heartbeat; do not click
  // sync. Native periodic sync must fetch the new revision while hidden.
  const nodeId=execFileSync(control,['--add-node',data,'Windows preview relay'],{encoding:'utf8',timeout:20000,windowsHide:true}).trim()
  const created=await manage('mappings','POST',admin,{device_id:device.id,node_id:nodeId,protocol:'tcp',local_port:localPort,bind_port:24001})
  if(created.status!==201)throw Error('management draft creation failed')
  const managedMapping=await created.json()
  const udpCreated=await manage('mappings','POST',admin,{device_id:device.id,node_id:nodeId,protocol:'udp',local_port:localPort,bind_port:24002})
  if(udpCreated.status!==201)throw Error('UDP desired draft creation failed')
  const udpMapping=await udpCreated.json()
  if(udpMapping.enabled!==false||udpMapping.domain_id!==null)throw Error('UDP draft incorrectly activated')
  const managementHwnd=await until('management native HWND',windowHandle)
  windowAction(managementHwnd,'close')
  await until('management window hidden',()=>windowAction(managementHwnd,'visible')==='False')
  const updated=await until('native automatic heartbeat while hidden',async()=>{
    const r=await manage('devices/'+device.id+'/status','GET',admin)
    if(r.status!==200)return false
    const s=await r.json()
    return s.management_online&&s.configuration_current&&s.reported_revision>heartbeat.reported_revision&&s.last_seen_at>heartbeat.last_seen_at&&s.reported_state==='idle'?s:null
  },65000)
  report.native_management_auto_heartbeat_hidden=true
  trayMenu('show')
  await until('management tray restored',()=>windowAction(managementHwnd,'visible')==='True')
  await waitText('管理配置版本：'+updated.reported_revision)
  await waitText('TCP · 本地 '+managedMapping.local_port+' → 中转 '+managedMapping.bind_port+' · 草稿禁用')
  await waitText('UDP · 本地 '+udpMapping.local_port+' → 中转 '+udpMapping.bind_port+' · 草稿禁用')
  // Real native process restart; DPAPI saved enrollment must be restored
  // and heartbeat sent without another enrollment or manual sync.
  trayMenu('quit')
  // until() deliberately rejects any app exit. An intentional restart
  // instead requires this exact child to exit with code zero, just as the
  // final tray quit gate does. Never accept a crash or force-kill here.
  const managementExitDeadline=Date.now()+20000
  while(app.exitCode===null&&app.signalCode===null&&Date.now()<managementExitDeadline) await sleep(200)
  if(app.exitCode!==0) throw Error('management tray quit did not exit normally')
  report.native_management_restart_clean_exit=true
  if(socket)socket.close()
  for(const request of pending.values()){
    clearTimeout(request.timer)
    request.fail(Error('CDP session closed for intentional restart'))
  }
  pending.clear()
  // A fresh CDP port/profile avoids attaching to a still-shutting-down
  // WebView2 child. The real per-user DPAPI file must survive independently.
  removeDebugPolicy()
  const debugReservation=tcpServer()
  const restartDebugPort=await listen(debugReservation)
  await close(debugReservation)
  installDebugPolicy(restartDebugPort)
  app=launch(exe,[],{...process.env,WEBVIEW2_USER_DATA_FOLDER:join(work,'webview-restart')})
  await connectCdp(restartDebugPort)
  await waitText('已配对 ID：'+device.id)
  await until('restarted desktop form ready',()=>evaluate('!!document.querySelector("input[placeholder=\\\"relay.example.com:2333\\\"]:not(:disabled)")'))
  await until('automatic heartbeat after app restart',async()=>{
    const r=await manage('devices/'+device.id+'/status','GET',admin)
    if(r.status!==200)return false
    const s=await r.json()
    return s.configuration_current&&s.last_seen_at>updated.last_seen_at
  },65000)
  report.native_management_saved_credential_restart=true
  if((await manage('devices/'+device.id+'/revoke','POST',admin)).status!==204)throw Error('management revoke failed')
  await until('automatic revocation recognized',()=>has('认证拒绝，自动同步已停止'),65000)
  await waitText('管理凭据无效或已吊销')
  const revoked=await manage('devices/'+device.id+'/status','GET',admin)
  const revokedState=await revoked.json()
  if(revoked.status!==200||revokedState.enabled||revokedState.management_online||revokedState.last_seen_at!==null)throw Error('revoked device still reports online')
  if(!await evaluate('[...document.querySelectorAll("button")].some(b=>b.textContent.trim()==="同步管理状态"&&b.disabled)'))throw Error('revoked sync still enabled')
  report.native_management_revocation_stops_automatic_sync=true
  if(await has('配置元数据及管理心跳同步成功'))throw Error('stale management status survived revoke')
  await evaluate('document.querySelector("input[aria-label=\\\"确认移除管理凭据\\\"]").click()')
  await click('移除管理凭据')
  await waitText('本地管理凭据已移除')
  try{await readFile(managementFile);throw Error('management credential was not removed')}
  catch(e){if(e.code!=='ENOENT')throw e}
  report.real_management_pairing_dpapi_heartbeat_and_revocation=true
  await terminate(management)
  management=null
  await click('＋ 添加映射')
  await until('two mappings', () => evaluate('document.querySelectorAll(".mapping").length===2'))
  await evaluate('document.querySelectorAll("button[aria-label=\\"删除映射\\"]")[1].click()')
  await until('one mapping', () => evaluate('document.querySelectorAll(".mapping").length===1'))
  report.mapping_add_remove = true
  await field('input[placeholder="relay.example.com:2333"]', '127.0.0.1:' + relayPort)
  await field('input[placeholder="X25519 公钥（Base64）"]', publicKey)
  await field('input[aria-label="本地端口"]', localPort)
  await field('input[aria-label="映射授权 Token"]', token)
  await click('检测本地端口')
  await waitText('TCP 可达')
  report.port_probe = true
  // Existing UI ignores clicks while a brief status poll is in progress.
  // Retry only while it is still visibly idle, never after a transition.
  await until('start button accepted', async () => {
    if (await has('进程运行中')) return true
    if (await has('处理中…')) return false
    await click('启动隧道')
    await sleep(400)
    return has('进程运行中')
  })
  report.start_clicked = true
  const url = 'http://127.0.0.1:' + mappedPort + '/'
  await until('real encrypted HTTP response', async () => await get(url) === body, 35000)
  report.encrypted_http = true
  await until('actual visible traffic counters', async () => {
    return evaluate('(()=>{const s=[...document.querySelectorAll("section")].find(e=>e.querySelector("h2")?.textContent==="桌面隧道流量");return !!s&&[...s.querySelectorAll(".summary span")].filter(e=>/^累计 [1-9][0-9.]* (B|KiB|MiB|GiB|TiB)$/.test(e.textContent.trim())).length>=2})()')
  })
  report.traffic_visible = true
  const hwnd = await until('native HWND', windowHandle)
  windowAction(hwnd,'close')
  await until('native window hidden', () => windowAction(hwnd,'visible') === 'False')
  report.native_close_hides = true
  await until('hidden window tunnel still forwards', async () => await get(url) === body, 10000)
  report.hidden_tunnel_works = true
  // Tao 0.37.3 caches visibility in WindowState. External ShowWindowAsync
  // bypasses set_visible/apply_diff, leaving the next hide a possible no-op.
  // Restore through the real product tray menu instead, then independently
  // observe the original HWND with Win32. Never force visibility from the test.
  trayMenu('show')
  await until('first tray restore makes native window visible', () => windowAction(hwnd,'visible') === 'True')
  report.native_restore = true
  report.tray_first_restore_clicked = true
  await until('first tray restore preserves forwarding', async () => await get(url) === body, 10000)
  await until('stop button accepted', async () => {
    if (await has('已停止') && !await has('进程运行中') && !await has('处理中…')) return true
    if (await has('处理中…')) return false
    await click('停止隧道')
    await sleep(400)
    return !await has('进程运行中') && await has('已停止')
  })
  report.stop_clicked = true
  await until('forwarding stopped', async () => await get(url) !== body, 15000)
  report.forwarding_stopped = true
  await until('history visible', () => evaluate('(()=>{const s=[...document.querySelectorAll("section")].find(e=>e.querySelector("h2")?.textContent==="桌面隧道流量");return !!s&&[...s.querySelectorAll(".summary div")].some(e=>e.querySelector("small")?.textContent==="历史累计上传"&&/^[1-9][0-9.]* (B|KiB|MiB|GiB|TiB)$/.test(e.querySelector("strong")?.textContent.trim()))})()'))
  report.history_visible = true

  // Actual installed desktop mixed TCP/UDP session via the same real form.
  await until('desktop editable for UDP',()=>evaluate('!!document.querySelector("select[aria-label=\\"映射协议\\"]:not(:disabled)")'))
  await click('＋ 添加映射')
  await until('UDP mapping row',()=>evaluate('document.querySelectorAll(".mapping-group").length===2'))
  const second='.mapping-group + .mapping-group '
  await field(second+'input[aria-label="映射名称"]','udp_echo')
  await field(second+'input[aria-label="本地端口"]',udpLocal)
  await field(second+'input[aria-label="映射授权 Token"]',udpToken)
  await field(second+'select[aria-label="映射协议"]','udp')
  await waitText('UDP 不支持 TCP 端口探测')
  if(!await evaluate('document.querySelectorAll(".port-actions button")[1].disabled'))throw Error('UDP misleading TCP probe enabled')
  await until('mixed start accepted',async()=>{
    if(await has('进程运行中'))return true
    if(await has('处理中…'))return false
    await click('启动隧道')
    return false
  })
  async function udpRoundTrip(){
    const client=udpSocket('udp4')
    const nonce=randomBytes(128)
    return new Promise(ok=>{
      let settled=false
      const finish=v=>{if(settled)return;settled=true;clearTimeout(timer);try{client.close()}catch{};ok(v)}
      const timer=setTimeout(()=>finish(false),900)
      client.on('error',()=>finish(false))
      client.on('message',(data,peer)=>{if(peer.address==='127.0.0.1'&&peer.port===udpMapped&&data.equals(nonce))finish(true)})
      client.send(nonce,udpMapped,'127.0.0.1',err=>{if(err)finish(false)})
    })
  }
  await until('actual mixed TCP UDP forwarding',async()=>await get(url)===body&&await udpRoundTrip(),35000)
  await waitText('含 UDP 的会话暂不计量（包括混合会话中的 TCP）；历史仅显示已保存的 TCP 数据。')
  await until('mixed session no false counters',()=>evaluate('(()=>{const s=[...document.querySelectorAll("section")].find(e=>e.querySelector("h2")?.textContent==="桌面隧道流量");return s?.querySelector(".section-title span")?.textContent==="未计量 / 未启动"})()'))
  report.real_installed_desktop_mixed_udp_forward_and_unmeasured=true
  await until('mixed stop accepted',async()=>{
    if(await has('已停止')&&!await has('进程运行中')&&!await has('处理中…'))return true
    if(await has('处理中…'))return false
    await click('停止隧道')
    return false
  })
  await until('mixed actual forwarding stopped',async()=>await get(url)!==body&&!await udpRoundTrip(),15000)
  await until('mixed editable',()=>evaluate('!document.querySelectorAll("button[aria-label=\\"删除映射\\"]")[1].disabled'))
  await evaluate('document.querySelectorAll("button[aria-label=\\"删除映射\\"]")[1].click()')
  await until('TCP only restored',()=>evaluate('document.querySelectorAll(".mapping").length===1&&document.querySelector("select[aria-label=\\"映射协议\\"]").value==="tcp"'))
  report.real_installed_desktop_mixed_udp_stop_and_tcp_restore=true

  // The desktop tunnel has stopped. The same form now provisions a fresh
  // SCM service using the installed app's actual Vue button and Rust IPC.
  await until('desktop form editable', () => evaluate('!!document.querySelector("input[placeholder=\\"relay.example.com:2333\\"]:not(:disabled)")'))
  const beforeDirs = new Set((await readdir(process.env.ProgramData)).filter(n=>/^LocalTunnelPreview-[0-9a-f]{32}$/.test(n)))
  const checked = await evaluate('(()=>{const e=document.querySelector("input[aria-label=\\\"确认部署新服务\\\"]");if(!e||e.disabled)return false;if(!e.checked)e.click();return e.checked})()')
  if (!checked) throw Error('provision confirmation unavailable')
  await serviceClick('一键部署新服务')
  try {
    serviceName = await until('new generated service name', async () => {
      const name = await evaluate('document.querySelector("input[placeholder=\\"LocalTunnelPreview-…\\"]")?.value')
      return typeof name==='string' && /^LocalTunnelPreview-[0-9a-f]{32}$/.test(name) && !beforeDirs.has(name) ? name : null
    }, 45000)
  } catch(e) {
    // If UI failed after provisioning, recover only a unique fresh fixture.
    const created = (await readdir(process.env.ProgramData)).filter(n=>/^LocalTunnelPreview-[0-9a-f]{32}$/.test(n)&&!beforeDirs.has(n))
    if (created.length===1) serviceName=created[0]
    throw e
  }
  const root = servicePath(serviceName)
  const profilePath = join(root,'service-profile.bin')
  const historyPath = join(root,'history','traffic-history.json')
  await waitStat('服务状态','已停止')
  await waitStat('启动方式','手动')
  const initial = statusCli(serviceName)
  if(initial.state!=='stopped'||initial.startup!=='manual') throw Error('unexpected provisioned SCM state')
  const originalProfile = await readFile(profilePath)
  if(originalProfile.includes(Buffer.from(token))) throw Error('plaintext fixture token in service profile')
  report.service_provisioned = true
  await serviceClick('开启开机自启')
  await waitStat('启动方式','自动')
  await serviceClick('设为手动启动')
  await waitStat('启动方式','手动')
  report.service_startup_controls = true
  await serviceClick('开启故障恢复')
  await waitText('故障恢复：已启用')
  await serviceClick('关闭故障恢复')
  await waitText('故障恢复：已关闭')
  report.service_recovery_controls = true
  await serviceClick('启动服务')
  await waitStat('服务状态','宿主运行中')
  await until('real SCM HTTP response',async()=>await get(url)===body,35000)
  report.service_real_http = true
  await until('visible SCM traffic',()=>evaluate('(()=>{const s=[...document.querySelectorAll("section")].find(e=>e.querySelector("h2")?.textContent==="Windows 后台服务");return !!s&&[...s.querySelectorAll(".summary span")].filter(e=>/^累计 [1-9][0-9.]* (B|KiB|MiB|GiB|TiB)$/.test(e.textContent.trim())).length>=2})()'))
  report.service_traffic_visible = true
  await serviceClick('停止服务')
  await waitStat('服务状态','已停止')
  await until('SCM forwarding stopped',async()=>await get(url)!==body,15000)
  report.service_stopped = true
  const savedBefore=JSON.parse(await readFile(historyPath,'utf8'))
  if(savedBefore.uploadBytes<Buffer.byteLength(body)||savedBefore.downloadBytes<=0) throw Error('missing real service history')

  // Update the stopped service to a second independent local HTTP fixture.
  const changedBody=randomBytes(56).toString('hex')
  alternate=httpServer((_req,res)=>{res.writeHead(200,{'Content-Length':Buffer.byteLength(changedBody)});res.end(changedBody)})
  const alternatePort=await listen(alternate)
  await field('input[aria-label="本地端口"]',alternatePort)
  await field('input[placeholder="'+serviceName+'"]',serviceName)
  await serviceClick('使用下方表单更新服务配置')
  await waitStat('启动方式','禁用')
  await waitStat('服务状态','已停止')
  const updatedProfile=await readFile(profilePath)
  if(updatedProfile.equals(originalProfile)||updatedProfile.includes(Buffer.from(token))) throw Error('updated service profile not encrypted/replaced')
  report.service_config_updated=true
  await serviceClick('设为手动启动')
  await waitStat('启动方式','手动')
  await serviceClick('启动服务')
  await waitStat('服务状态','宿主运行中')
  await until('updated SCM mapping response',async()=>await get(url)===changedBody,35000)
  report.service_updated_http=true
  await serviceClick('停止服务')
  await waitStat('服务状态','已停止')
  await until('updated mapping stopped',async()=>await get(url)!==changedBody,15000)
  const savedAfter=JSON.parse(await readFile(historyPath,'utf8'))
  if(savedAfter.uploadBytes<savedBefore.uploadBytes+Buffer.byteLength(changedBody)||savedAfter.downloadBytes<=savedBefore.downloadBytes) throw Error('service update lost history')
  await field('input[placeholder="'+serviceName+'"]',serviceName)
  await serviceClick('注销服务注册')
  await waitText('已注销 SCM 注册')
  await until('SCM registration absent',()=>scAbsent(serviceName),25000)
  report.service_unregistered=true
  if(!(await readFile(profilePath)).equals(updatedProfile)||JSON.stringify(JSON.parse(await readFile(historyPath,'utf8')))!==JSON.stringify(savedAfter)) throw Error('unregister changed protected data')
  report.service_data_preserved=true

  // Repeat the native tray gate after the full SCM GUI lifecycle.
  // Reuse the alternate target now shown in the desktop form.
  async function startDesktopAgain() {
    await until('desktop starts for tray test',async()=>{
      if(await has('进程运行中')) return true
      if(await has('处理中…')) return false
      await click('启动隧道')
      await sleep(400)
      return has('进程运行中')
    })
    await until('tray test HTTP response',async()=>await get(url)===changedBody,35000)
  }
  await startDesktopAgain()
  // Reuse the actual main window proven by the first WM_CLOSE / restore.
  // Get-Process.MainWindowHandle can select another visible top-level window
  // of the same PID after restoring or showing auxiliary WebView windows.
  const trayHwnd=hwnd
  report.tray_same_main_hwnd=windowHandle()===trayHwnd
  report.tray_original_window_visible=windowAction(trayHwnd,'visible')==='True'
  if(!report.tray_original_window_visible) throw Error('original main window is not visible before tray close')
  windowAction(trayHwnd,'close')
  await until('original main window hidden for tray restore',()=>windowAction(trayHwnd,'visible')==='False')
  report.tray_original_window_hidden=true
  await until('second hidden window still forwards',async()=>await get(url)===changedBody,10000)
  report.tray_second_hidden_http=true
  trayMenu('show')
  await until('tray show restores window',()=>windowAction(trayHwnd,'visible')==='True')
  report.tray_show_clicked=true
  await until('tray restore keeps HTTP working',async()=>await get(url)===changedBody,10000)
  trayMenu('stop')
  await until('tray stops desktop tunnel',async()=>!await has('进程运行中')&&await has('已停止'))
  await until('tray stop breaks forwarding',async()=>await get(url)!==changedBody,15000)
  report.tray_stop_clicked=true
  await startDesktopAgain()
  // Quit while actual traffic is flowing, not an already-idle process.
  trayMenu('quit')
  report.tray_quit_clicked=true
  const exitDeadline=Date.now()+20000
  while(app.exitCode===null&&Date.now()<exitDeadline) await sleep(200)
  if(app.exitCode!==0) throw Error('tray quit did not exit normally')
  report.tray_quit_clean_exit=true
  const stopDeadline=Date.now()+15000
  while(await get(url)===changedBody&&Date.now()<stopDeadline) await sleep(250)
  if(await get(url)===changedBody) throw Error('tunnel remained after tray quit')
  report.tray_quit_forwarding_stopped=true
} finally {
  try {
    if (socket) socket.close()
    await terminate(app)
    await terminate(management)
    if(managementCreated&&managementFile)await rm(managementFile,{force:true})
    if (serviceName) {
      cleanupTestService(serviceName)
      if (scAbsent(serviceName)) {
        // Remove only the random fixture created in this isolated CI test.
        await rm(servicePath(serviceName),{recursive:true,force:true,maxRetries:5,retryDelay:300})
      } else {
        throw Error('disposable GUI service cleanup failed')
      }
    }
    await terminate(relay)
    if (udpFixture) await new Promise(ok=>udpFixture.close(ok))
    if (alternate) { alternate.closeAllConnections(); await close(alternate) }
    if (fixture) { fixture.closeAllConnections(); await close(fixture) }
  } finally {
    try { removeDebugPolicy() }
    finally {
      await writeFile(evidence, JSON.stringify(report,null,2))
      await rm(work, { recursive:true, force:true, maxRetries:5, retryDelay:300 }).catch(()=>{})
    }
  }
}

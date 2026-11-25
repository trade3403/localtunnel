// Real installed WebView2 UI + Rust IPC + encrypted TCP. Node >=22.
// Test-only loopback CDP endpoint; never enable debugging in app config.
// No saved real credentials, screenshots, or payload logs.
import { spawn, execFileSync } from 'node:child_process'
import { createServer as tcpServer } from 'node:net'
import { createServer as httpServer } from 'node:http'
import { randomBytes } from 'node:crypto'
import { mkdtemp, writeFile, rm, readFile, readdir } from 'node:fs/promises'
import { dirname, join, resolve, basename } from 'node:path'
import { tmpdir } from 'node:os'

const [exeArg, evidenceArg] = process.argv.slice(2)
if (!exeArg || !evidenceArg || process.platform !== 'win32') throw Error('Windows installed GUI test arguments required')
if (process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted' || process.env.RUNNER_OS !== 'Windows') {
  throw Error('temporary CDP policy is restricted to disposable GitHub-hosted Windows runners')
}
const exe = resolve(exeArg)
const evidence = resolve(evidenceArg)
const engine = join(dirname(exe), 'engine', 'rathole.exe')
const work = await mkdtemp(join(tmpdir(), 'localtunnel-gui-'))
const report = { scope: 'installed WebView2 desktop and SCM DOM controls + real IPC + loopback encrypted HTTP + native WM_CLOSE; not physical tray menu click or public E2E',
  ui_ready: false, mapping_add_remove: false, port_probe: false,
  start_clicked: false, encrypted_http: false, traffic_visible: false,
  native_close_hides: false, hidden_tunnel_works: false, native_restore: false,
  stop_clicked: false, forwarding_stopped: false, history_visible: false }
let app, relay, socket, fixture, policy, alternate
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
    '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr h,int n);',
    '[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);',
    '}',
    "'@",
    '$h=[IntPtr]::new(' + handle + '); $owner=[uint32]0; [void][GuiNative]::GetWindowThreadProcessId($h,[ref]$owner);',
    'if($owner -ne ' + app.pid + '){throw "unexpected window owner"}',
    action === 'close' ? 'if(![GuiNative]::PostMessage($h,0x10,[IntPtr]::Zero,[IntPtr]::Zero)){throw "WM_CLOSE failed"}' :
      action === 'show' ? '[void][GuiNative]::ShowWindowAsync($h,9)' :
      '[Console]::WriteLine([GuiNative]::IsWindowVisible($h))'
  ].join('\r\n')
  return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script,'utf16le').toString('base64')], { encoding: 'utf8', timeout: 10000 }).trim()
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
  const config = join(work, 'server.toml')
  await writeFile(config, [
    '[server]', 'bind_addr = "127.0.0.1:' + relayPort + '"', 'heartbeat_interval = 5',
    '[server.transport]', 'type = "noise"', '[server.transport.noise]',
    'pattern = "Noise_NK_25519_ChaChaPoly_BLAKE2s"', 'local_private_key = "' + privateKey + '"',
    '[server.services.web]', 'type = "tcp"', 'token = "' + token + '"',
    'bind_addr = "127.0.0.1:' + mappedPort + '"', ''
  ].join('\n'))
  relay = launch(engine, [config])
  installDebugPolicy(debugPort)
  app = launch(exe, [], { ...process.env, WEBVIEW2_USER_DATA_FOLDER: join(work,'webview') })
  await connectCdp(debugPort)
  await until('ready enabled input', () => evaluate('!!document.querySelector("input[placeholder=\\"relay.example.com:2333\\"]:not(:disabled)")'))
  report.ui_ready = true
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
  // OS restore of this exact HWND only; physical tray menu click is separate.
  windowAction(hwnd,'show')
  await until('native window visible', () => windowAction(hwnd,'visible') === 'True')
  report.native_restore = true
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

  // The desktop tunnel has stopped. The same form now provisions a fresh
  // SCM service using the installed app's actual Vue button and Rust IPC.
  await until('desktop form editable', () => evaluate('!!document.querySelector("input[placeholder=\\"relay.example.com:2333\\"]:not(:disabled)")'))
  const beforeDirs = new Set((await readdir(process.env.ProgramData)).filter(n=>/^LocalTunnelPreview-[0-9a-f]{32}$/.test(n)))
  const checked = await evaluate('(()=>{const e=document.querySelector("input[type=checkbox]");if(!e||e.disabled)return false;if(!e.checked)e.click();return e.checked})()')
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
} finally {
  try {
    if (socket) socket.close()
    await terminate(app)
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

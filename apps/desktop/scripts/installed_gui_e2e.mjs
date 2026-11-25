// Real installed WebView2 UI + Rust IPC + encrypted TCP. Node >=22.
// Test-only loopback CDP endpoint; never enable debugging in app config.
// No saved real credentials, screenshots, or payload logs.
import { spawn, execFileSync } from 'node:child_process'
import { createServer as tcpServer } from 'node:net'
import { createServer as httpServer } from 'node:http'
import { randomBytes } from 'node:crypto'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { tmpdir } from 'node:os'

const [exeArg, evidenceArg] = process.argv.slice(2)
if (!exeArg || !evidenceArg || process.platform !== 'win32') throw Error('Windows installed GUI test arguments required')
const exe = resolve(exeArg)
const evidence = resolve(evidenceArg)
const engine = join(dirname(exe), 'engine', 'rathole.exe')
const work = await mkdtemp(join(tmpdir(), 'localtunnel-gui-'))
const report = { scope: 'installed WebView2 DOM controls + real IPC + loopback encrypted HTTP + native WM_CLOSE; not physical tray menu click or public E2E',
  ui_ready: false, mapping_add_remove: false, port_probe: false,
  start_clicked: false, encrypted_http: false, traffic_visible: false,
  native_close_hides: false, hidden_tunnel_works: false, native_restore: false,
  stop_clicked: false, forwarding_stopped: false, history_visible: false }
let app, relay, socket, fixture
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
    const list = await (await fetch('http://127.0.0.1:' + port + '/json/list', { signal: AbortSignal.timeout(2000) })).json()
    return list.find(t => t.type === 'page' && t.webSocketDebuggerUrl && /^https?:\/\/(tauri\.localhost|localhost)([:/]|$)/.test(t.url))?.webSocketDebuggerUrl
  }, 40000)
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
    '$h=[IntPtr]::new(' + handle + '); $owner=0u; [void][GuiNative]::GetWindowThreadProcessId($h,[ref]$owner);',
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
  app = launch(exe, [], { ...process.env, WEBVIEW2_USER_DATA_FOLDER: join(work,'webview'),
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: '--remote-debugging-port=' + debugPort + ' --remote-debugging-address=127.0.0.1' })
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
} finally {
  if (socket) socket.close()
  await terminate(app)
  await terminate(relay)
  if (fixture) { fixture.closeAllConnections(); await close(fixture) }
  await writeFile(evidence, JSON.stringify(report,null,2))
  await rm(work, { recursive:true, force:true, maxRetries:5, retryDelay:300 }).catch(()=>{})
}

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { invoke } from '@tauri-apps/api/core'

type Mapping = { id: number; name: string; localPort: number | null; token: string }
type Profile = { engine: string; remote: string; serverKey: string; mappings: { name: string; localPort: number }[] }
type StartRequest = Omit<Profile, 'mappings'> & { mappings: { name: string; localPort: number; token: string }[] }
type Status = { state: 'stopped' | 'running' | 'error'; detail: string; mappingCount: number }
const engine = ref('')
const remote = ref('')
const serverKey = ref('')
let nextId = 2
const mappings = ref<Mapping[]>([{ id: 1, name: 'web', localPort: 8080, token: '' }])
const status = ref<Status>({ state: 'stopped', detail: '正在获取进程状态', mappingCount: 0 })
const busy = ref(false)
const error = ref('')
const notice = ref('')
const portNotice = ref<Record<number, string>>({})
const ready = ref(false)
const running = computed(() => status.value.state === 'running')
const locked = computed(() => busy.value || running.value || !ready.value)
const label = computed(() => !ready.value ? '状态未知' : running.value ? '进程运行中' : status.value.state === 'error' ? '进程异常' : '已停止')
let timer: ReturnType<typeof setInterval> | undefined
let polling = false
async function refresh() {
  if (busy.value || polling) return
  polling = true
  try {
    status.value = await invoke<Status>('tunnel_status')
    ready.value = true
  } catch {
    ready.value = false
    error.value = '无法读取本地 Rust 服务状态。请使用桌面应用打开。'
  } finally { polling = false }
}
onMounted(() => { void refresh(); timer = setInterval(refresh, 1200) })
onUnmounted(() => { if (timer) clearInterval(timer) })
function add() {
  if (locked.value || mappings.value.length >= 64) return
  mappings.value.push({ id: nextId++, name: '', localPort: 8080, token: '' })
}
function remove(id: number) {
  if (!locked.value && mappings.value.length > 1) mappings.value = mappings.value.filter(m => m.id !== id)
}
async function profileAction(action: 'save' | 'load') {
  if (locked.value || polling) return
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    if (action === 'save') {
      if (mappings.value.some(m => !Number.isInteger(m.localPort) || Number(m.localPort) < 1 || Number(m.localPort) > 65535)) {
        throw new Error('请输入有效本地端口')
      }
      const profile: Profile = {
        engine: engine.value.trim(), remote: remote.value.trim(), serverKey: serverKey.value.trim(),
        mappings: mappings.value.map(m => ({ name: m.name.trim(), localPort: Number(m.localPort) }))
      }
      await invoke('save_profile', { profile })
      notice.value = '配置已保存（不包含授权 Token）'
    } else {
      const profile = await invoke<Profile | null>('load_profile')
      if (!profile) {
        notice.value = '尚未保存配置'
        return
      }
      engine.value = profile.engine
      remote.value = profile.remote
      serverKey.value = profile.serverKey
      mappings.value = profile.mappings.map(m => ({ ...m, id: nextId++, token: '' }))
      notice.value = '配置已读取，请重新填写授权 Token'
    }
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally { busy.value = false; void refresh() }
}
function currentRequest(): StartRequest {
  if (mappings.value.some(m => !Number.isInteger(m.localPort) || Number(m.localPort) < 1 || Number(m.localPort) > 65535)) {
    throw new Error('请输入 1–65535 的有效本地端口')
  }
  return {
    engine: engine.value.trim(), remote: remote.value.trim(), serverKey: serverKey.value.trim(),
    mappings: mappings.value.map(m => ({ name: m.name.trim(), localPort: Number(m.localPort), token: m.token }))
  }
}
async function protectedAction(action: 'save' | 'load' | 'forget') {
  if (locked.value || polling) return
  busy.value = true
  error.value = ''
  notice.value = ''
  try {
    if (action === 'save') {
      await invoke('save_protected_profile', { request: currentRequest() })
      notice.value = '已用当前 Windows 用户 DPAPI 加密保存配置及 Token'
    } else if (action === 'load') {
      const saved = await invoke<StartRequest | null>('load_protected_profile')
      if (!saved) { notice.value = '尚未保存加密凭据'; return }
      engine.value = saved.engine
      remote.value = saved.remote
      serverKey.value = saved.serverKey
      mappings.value = saved.mappings.map(m => ({ ...m, id: nextId++ }))
      notice.value = '已读取加密配置，未自动连接'
    } else {
      await invoke('forget_protected_profile')
      mappings.value.forEach(m => { m.token = '' })
      notice.value = '已删除保存的加密凭据并清空当前 Token'
    }
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally { busy.value = false; void refresh() }
}
async function probe(mapping: Mapping) {
  if (!ready.value || busy.value || !Number.isInteger(mapping.localPort) || Number(mapping.localPort) < 1 || Number(mapping.localPort) > 65535) return
  const port = Number(mapping.localPort)
  const id = mapping.id
  portNotice.value[id] = '检测中…'
  try {
    const open = await invoke<boolean>('check_local_port', { port })
    portNotice.value[id] = '端口 ' + port + (open ? ' TCP 可达' : ' TCP 不可达')
  } catch {
    portNotice.value[id] = '端口 ' + port + ' 检测失败'
  }
}
async function toggle() {
  if (!ready.value || busy.value || polling) return
  busy.value = true
  error.value = ''
  try {
    if (running.value) {
      status.value = await invoke<Status>('stop_tunnel')
    } else {
      if (mappings.value.some(m => !Number.isInteger(m.localPort) || Number(m.localPort) < 1 || Number(m.localPort) > 65535)) {
        throw new Error('请输入 1–65535 的有效本地端口')
      }
      status.value = await invoke<Status>('start_tunnel', { request: {
        engine: engine.value.trim(), remote: remote.value.trim(), serverKey: serverKey.value.trim(),
        mappings: mappings.value.map(m => ({ name: m.name.trim(), localPort: m.localPort, token: m.token }))
      } })
    }
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
  } finally { busy.value = false; void refresh() }
}
</script>

<template>
  <div class="shell">
    <aside>
      <div class="brand"><span class="brand-icon">LT</span><div>LocalTunnel<small>本地穿透客户端</small></div></div>
      <div class="nav-active">▦　连接与映射</div>
      <div class="side-note">V0.3 开发预览<br>Rust · Noise 加密隧道</div>
    </aside>
    <main>
      <header><div><p class="eyebrow">工作台 / 连接与映射</p><h1>内网穿透</h1><p class="muted">将本地服务连接到已授权的中转节点</p></div><span class="status" :class="{ online: ready && running }"><i></i>{{ label }}</span></header>
      <div class="summary">
        <div><small>映射配置</small><strong>{{ mappings.length }}</strong><span>最多 64 个映射</span></div>
        <div><small>已启动映射</small><strong>{{ ready ? status.mappingCount : '—' }}</strong><span>进程状态，非公网在线数</span></div>
        <div><small>隧道协议</small><strong class="protocol">Noise</strong><span>服务端公钥验证</span></div>
      </div>
      <form @submit.prevent="toggle">
        <section>
          <div class="section-title"><h2>中转节点</h2><span>服务端需提前配置同名映射</span></div>
          <div class="fields">
            <label>服务器地址<input v-model="remote" :disabled="locked" required placeholder="relay.example.com:2333" /></label>
            <label>服务器公钥<input v-model="serverKey" :disabled="locked" required autocomplete="off" placeholder="X25519 公钥（Base64）" /></label>
            <label class="wide">Rathole 引擎路径<input v-model="engine" :disabled="locked" required placeholder="C:\LocalTunnel\rathole.exe" /></label>
          </div>
          <p class="hint">仅使用已校验的官方引擎。普通保存不写入 Token；仅主动选择加密保存才保留凭据。</p>
          <div class="profile-actions">
            <button type="button" class="secondary" :disabled="locked" @click="profileAction('save')">保存配置</button>
            <button type="button" class="secondary" :disabled="locked" @click="profileAction('load')">读取配置</button>
            <button type="button" class="secondary" :disabled="locked" @click="protectedAction('save')">加密保存含 Token</button>
            <button type="button" class="secondary" :disabled="locked" @click="protectedAction('load')">读取加密配置</button>
            <button type="button" class="secondary" :disabled="locked" @click="protectedAction('forget')">删除加密凭据</button>
            <span v-if="notice" role="status">{{ notice }}</span>
          </div>
        </section>
        <section>
          <div class="section-title"><h2>本地映射</h2><button type="button" class="secondary" :disabled="locked || mappings.length >= 64" @click="add">＋ 添加映射</button></div>
          <div class="table-head"><span>映射名称</span><span>本地端口</span><span>独立授权 Token</span><span></span></div>
          <div v-for="mapping in mappings" :key="mapping.id" class="mapping-group"><div class="mapping">
            <input v-model="mapping.name" :disabled="locked" aria-label="映射名称" required maxlength="64" placeholder="web" />
            <input v-model.number="mapping.localPort" :disabled="locked" aria-label="本地端口" required type="number" min="1" max="65535" />
            <input v-model="mapping.token" :disabled="locked" aria-label="映射授权 Token" required type="password" autocomplete="off" minlength="32" maxlength="128" placeholder="输入授权 Token" />
            <button type="button" class="remove" :disabled="locked || mappings.length === 1" @click="remove(mapping.id)" aria-label="删除映射">×</button>
          </div><div class="port-actions"><button type="button" class="secondary" :disabled="busy || !ready" @click="probe(mapping)">检测本地端口</button><span role="status">{{ portNotice[mapping.id] || "未检测" }}</span></div></div>
          <p class="hint">端口检测只验证本地 TCP 可达性，不代表服务端认证或公网在线。目标地址固定为 127.0.0.1。停止隧道后可编辑配置；域名由服务端分配。</p>
        </section>
        <div class="actions">
          <div aria-live="polite"><strong>{{ label }}</strong><p>{{ status.detail }}</p><p v-if="error" class="error" role="alert">{{ error }}</p></div>
          <button class="primary" :class="{ danger: running }" :disabled="busy || !ready" :type="running ? 'button' : 'submit'" @click="running && toggle()">{{ busy ? '处理中…' : running ? '停止隧道' : '启动隧道' }}</button>
        </div>
      </form>
      <footer>开发预览 · 关闭窗口后保留在系统托盘 · 托盘中退出会停止隧道</footer>
    </main>
  </div>
</template>

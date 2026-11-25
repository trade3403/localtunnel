<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { invoke } from '@tauri-apps/api/core'

type Mapping = { id: number; name: string; localPort: number | null; token: string }
type Profile = { engine: string; remote: string; serverKey: string; mappings: { name: string; localPort: number }[] }
type StartRequest = Omit<Profile, 'mappings'> & { mappings: { name: string; localPort: number; token: string }[] }
type Status = { state: 'stopped' | 'running' | 'error'; detail: string; mappingCount: number }
type Transport = { state: 'inactive' | 'unknown' | 'established' | 'not_observed'; established: number | null; matchScope: 'none' | 'ip_port' | 'port_only' }
const transport = ref<Transport>({ state: 'inactive', established: null, matchScope: 'none' })
const transportLabel = computed(() => !ready.value || transport.value.state === 'unknown' ? '未知' :
  transport.value.state === 'inactive' ? '未启动' :
  transport.value.state === 'not_observed' ? '未观察到' : String(transport.value.established))
const transportHint = computed(() => transport.value.matchScope === 'port_only' ? '按中转端口匹配候选 TCP；未验证域名/认证' :
  transport.value.matchScope === 'ip_port' ? '按中转 IP 和端口匹配；未验证认证' : '非公网在线证明')
type ServiceTraffic = { hostPid: number; enginePid: number; sampledAtMs: number; uploadBytes: number; downloadBytes: number; uploadBytesPerSecond: number | null; downloadBytesPerSecond: number | null }
type ServiceSnapshot = { state: string; startup: string; recovery: 'enabled' | 'disabled' | 'unverified'; hostPid: number | null; win32ExitCode: number; serviceExitCode: number; traffic: ServiceTraffic | null; history: { uploadBytes: number; downloadBytes: number; savedAtMs: number } | null }
const serviceName = ref('')
const watchedService = ref('')
const serviceSnapshot = ref<ServiceSnapshot | null>(null)
const serviceError = ref('')
const serviceActionError = ref('')
const serviceActionNotice = ref('')
const serviceBusy = ref(false)
type ServiceAction = 'check' | 'start' | 'stop' | 'autostart-on' | 'autostart-off' | 'recovery-on' | 'recovery-off'
async function serviceAction(action: ServiceAction) {
  const name = watchedService.value
  if (!name || !serviceSnapshot.value || serviceBusy.value || serviceName.value.trim() !== name) return
  serviceBusy.value = true
  serviceGeneration++
  serviceActionError.value = ''
  serviceActionNotice.value = ''
  try {
    await invoke('manage_service', { name, action })
    serviceActionNotice.value = '操作成功，正在读取 SCM 最新状态'
  } catch (e) {
    serviceActionError.value = '操作失败（请检查管理员权限、服务配置及状态）：' + String(e)
  } finally {
    serviceSnapshot.value = null
    serviceBusy.value = false
    void refreshService()
  }
}
let servicePolling = false
let serviceGeneration = 0
const serviceStateLabels: Record<string, string> = { stopped: '已停止', starting: '启动中', stopping: '停止中', running: '宿主运行中', paused: '已暂停', transitioning: '切换中', unknown: '未知' }
const startupLabels: Record<string, string> = { automatic: '自动', manual: '手动', disabled: '禁用', unknown: '未知' }
async function refreshService() {
  const name = watchedService.value
  if (!name || servicePolling || serviceBusy.value) return
  servicePolling = true
  const generation = serviceGeneration
  try {
    const result = await invoke<ServiceSnapshot>('service_status', { name })
    if (serviceGeneration === generation) {
      serviceSnapshot.value = result
      serviceError.value = ''
    }
  } catch {
    if (serviceGeneration === generation) {
      serviceSnapshot.value = null
      serviceError.value = '无法读取服务：未注册、身份不符或查询权限不足'
    }
  } finally { servicePolling = false }
}
function watchService() {
  if (serviceBusy.value) return
  serviceActionError.value = ''
  serviceActionNotice.value = ''
  serviceGeneration++
  serviceSnapshot.value = null
  serviceError.value = ''
  const name = serviceName.value.trim()
  watchedService.value = ''
  if (!/^LocalTunnelPreview-[0-9a-fA-F]{32}$/.test(name)) {
    serviceError.value = '请输入完整的 LocalTunnelPreview 服务名称'
    return
  }
  watchedService.value = name
  void refreshService()
}
function unwatchService() {
  if (serviceBusy.value) return
  serviceActionError.value = ''
  serviceActionNotice.value = ''
  serviceGeneration++
  watchedService.value = ''
  serviceSnapshot.value = null
  serviceError.value = ''
}
type Traffic = { state: 'inactive' | 'unknown' | 'measured'; uploadBytes: number | null; downloadBytes: number | null; uploadBytesPerSecond: number | null; downloadBytesPerSecond: number | null }
const traffic = ref<Traffic | null>(null)
type TrafficHistory = { saved: { uploadBytes: number; downloadBytes: number; savedAtMs: number } | null; writeFailed: boolean }
const trafficHistory = ref<TrafficHistory | null>(null)
const historyError = ref(false)
function formatBytes(value: number | null | undefined, rate = false) {
  if (value == null || !Number.isFinite(value) || value < 0) return '—'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let i = 0
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i++ }
  return value.toFixed(i === 0 ? 0 : 2) + ' ' + units[i] + (rate ? '/s' : '')
}
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
    try { traffic.value = await invoke<Traffic>('traffic_status') } catch { traffic.value = null }
    try {
      trafficHistory.value = await invoke<TrafficHistory>('traffic_history')
      historyError.value = false
    } catch { trafficHistory.value = null; historyError.value = true }
    try {
      transport.value = await invoke<Transport>('transport_status')
    } catch {
      transport.value = { state: 'unknown', established: null, matchScope: 'none' }
    }
  } catch {
    ready.value = false
    traffic.value = null
    trafficHistory.value = null
    historyError.value = true
    error.value = '无法读取本地 Rust 服务状态。请使用桌面应用打开。'
  } finally { polling = false }
}
onMounted(() => { void refresh(); timer = setInterval(() => { void refresh(); void refreshService() }, 1200) })
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
      <header><div><p class="eyebrow">工作台 / 连接与映射</p><h1>内网穿透</h1><p class="muted">将本地服务连接到已授权的中转节点 · Noise 加密</p></div><span class="status" :class="{ online: ready && running }"><i></i>{{ label }}</span></header>
      <div class="summary">
        <div><small>映射配置</small><strong>{{ mappings.length }}</strong><span>最多 64 个映射</span></div>
        <div><small>已启动映射</small><strong>{{ ready ? status.mappingCount : '—' }}</strong><span>进程状态，非公网在线数</span></div>
        <div><small>中转 TCP 连接</small><strong class="protocol">{{ transportLabel }}</strong><span>{{ transportHint }}</span></div>
      </div>
      <section>
        <div class="section-title"><h2>桌面隧道流量</h2><span>{{ traffic?.state === 'measured' ? '实际 TCP 数据' : '未计量 / 未启动' }}</span></div>
        <div class="summary">
          <div><small>上传速度</small><strong class="protocol">{{ formatBytes(traffic?.uploadBytesPerSecond, true) }}</strong><span>累计 {{ formatBytes(traffic?.uploadBytes) }}</span></div>
          <div><small>下载速度</small><strong class="protocol">{{ formatBytes(traffic?.downloadBytesPerSecond, true) }}</strong><span>累计 {{ formatBytes(traffic?.downloadBytes) }}</span></div>
          <div><small>计量范围</small><strong class="protocol">本次会话</strong><span>不含加密/TCP 开销</span></div>
        </div>
        <p class="hint">以上为本次桌面会话；历史统计每 5 秒保存，正常停止时保存最终值。</p>
        <div class="summary">
          <div><small>历史累计上传</small><strong class="protocol">{{ formatBytes(trafficHistory?.saved?.uploadBytes) }}</strong><span>本机已保存</span></div>
          <div><small>历史累计下载</small><strong class="protocol">{{ formatBytes(trafficHistory?.saved?.downloadBytes) }}</strong><span>本机已保存</span></div>
          <div><small>最近保存</small><strong class="protocol">{{ trafficHistory?.saved ? new Date(trafficHistory.saved.savedAtMs).toLocaleTimeString() : '—' }}</strong><span>仅桌面模式</span></div>
        </div>
        <p v-if="historyError || trafficHistory?.writeFailed" class="error" role="alert">历史流量读取或保存失败，已保留原记录。</p>
        <p class="hint">历史包含已保存的本次会话流量，不能重复相加；异常断电可能丢失最后一段未保存数据。不包含协议开销、后台服务或计费数据。</p>
      </section>
      <section>
        <div class="section-title"><h2>Windows 后台服务</h2><span>SCM 服务管理</span></div>
        <div class="fields">
          <label class="wide">已注册服务名称<input v-model="serviceName" :disabled="serviceBusy" maxlength="51" placeholder="LocalTunnelPreview-…" /></label>
        </div>
        <div class="profile-actions">
          <button type="button" class="secondary" :disabled="serviceBusy" @click="watchService">监测服务</button>
          <button type="button" class="secondary" :disabled="!watchedService || serviceBusy" @click="unwatchService">停止监测</button>
        </div>
        <p v-if="watchedService" class="hint">监测：{{ watchedService }}</p>
        <div v-if="serviceSnapshot" class="summary" aria-live="polite">
          <div><small>服务状态</small><strong class="protocol">{{ serviceStateLabels[serviceSnapshot.state] || '未知' }}</strong><span>非公网在线证明</span></div>
          <div><small>启动方式</small><strong class="protocol">{{ startupLabels[serviceSnapshot.startup] || '未知' }}</strong><span>SCM 实际配置</span></div>
          <div><small>宿主 PID</small><strong>{{ serviceSnapshot.hostPid ?? '—' }}</strong><span>退出码 {{ serviceSnapshot.win32ExitCode }} / {{ serviceSnapshot.serviceExitCode }}</span></div>
        </div>
        <p v-else-if="watchedService && !serviceError" class="hint">读取服务状态中…</p>
        <div v-if="serviceSnapshot?.traffic" class="summary">
          <div><small>服务上传速度</small><strong class="protocol">{{ formatBytes(serviceSnapshot.traffic.uploadBytesPerSecond, true) }}</strong><span>累计 {{ formatBytes(serviceSnapshot.traffic.uploadBytes) }}</span></div>
          <div><small>服务下载速度</small><strong class="protocol">{{ formatBytes(serviceSnapshot.traffic.downloadBytesPerSecond, true) }}</strong><span>累计 {{ formatBytes(serviceSnapshot.traffic.downloadBytes) }}</span></div>
          <div><small>计量引擎 PID</small><strong>{{ serviceSnapshot.traffic.enginePid }}</strong><span>本次引擎会话</span></div>
        </div>
        <p v-else-if="serviceSnapshot?.state === 'running'" class="hint">流量快照暂不可用（权限不足、恢复中或尚未采样）。</p>
        <div v-if="serviceSnapshot?.history" class="summary">
          <div><small>服务历史累计上传</small><strong class="protocol">{{ formatBytes(serviceSnapshot.history.uploadBytes) }}</strong><span>已保存</span></div>
          <div><small>服务历史累计下载</small><strong class="protocol">{{ formatBytes(serviceSnapshot.history.downloadBytes) }}</strong><span>已保存</span></div>
          <div><small>最近保存</small><strong class="protocol">{{ new Date(serviceSnapshot.history.savedAtMs).toLocaleTimeString() }}</strong><span>独立于桌面历史</span></div>
        </div>
        <p v-else-if="serviceSnapshot" class="hint">服务历史暂无可读记录（未配置、未保存或权限不足）。</p>
        <p v-if="serviceSnapshot?.history" class="hint">已保存历史含本次已保存增量，不与会话流量重复相加；强制结束可能丢失未保存增量。</p>
        <div v-if="serviceSnapshot" class="profile-actions">
          <button type="button" class="secondary" :disabled="serviceBusy || serviceName.trim() !== watchedService" @click="serviceAction('check')">检查服务配置</button>
          <button type="button" class="secondary" :disabled="serviceBusy || serviceName.trim() !== watchedService || serviceSnapshot.state !== 'stopped' || serviceSnapshot.startup === 'disabled'" @click="serviceAction('start')">启动服务</button>
          <button type="button" class="secondary" :disabled="serviceBusy || serviceName.trim() !== watchedService || serviceSnapshot.state !== 'running'" @click="serviceAction('stop')">停止服务</button>
          <button type="button" class="secondary" :disabled="serviceBusy || serviceName.trim() !== watchedService || serviceSnapshot.startup === 'automatic'" @click="serviceAction('autostart-on')">开启开机自启</button>
          <button type="button" class="secondary" :disabled="serviceBusy || serviceName.trim() !== watchedService || serviceSnapshot.startup === 'manual'" @click="serviceAction('autostart-off')">设为手动启动</button>
          <button type="button" class="secondary" :disabled="serviceBusy || serviceName.trim() !== watchedService || serviceSnapshot.recovery === 'enabled'" @click="serviceAction('recovery-on')">开启故障恢复</button>
          <button type="button" class="secondary" :disabled="serviceBusy || serviceName.trim() !== watchedService || serviceSnapshot.recovery === 'disabled'" @click="serviceAction('recovery-off')">关闭故障恢复</button>
          <span>故障恢复：{{ serviceSnapshot.recovery === 'enabled' ? '已启用' : serviceSnapshot.recovery === 'disabled' ? '已关闭' : '默认 / 未验证' }}</span>
        </div>
        <p v-if="serviceBusy" class="hint" role="status">正在执行服务操作…</p>
        <p v-if="serviceActionNotice" class="hint" role="status">{{ serviceActionNotice }}</p>
        <p v-if="serviceActionError" class="error" role="alert">{{ serviceActionError }}</p>
        <p v-if="serviceError" class="error" role="alert">{{ serviceError }}</p>
        <p class="hint">仅管理已注册且已授权的预览服务。操作使用当前 Windows 权限，不自动提权；需管理员时请以管理员身份运行客户端。关闭客户端不停止独立后台服务。已排队的 SCM 恢复可能仍会执行。</p>
      </section>
      <form @submit.prevent="toggle">
        <section>
          <div class="section-title"><h2>中转节点</h2><span>服务端需提前配置同名映射</span></div>
          <div class="fields">
            <label>服务器地址<input v-model="remote" :disabled="locked" required placeholder="relay.example.com:2333" /></label>
            <label>服务器公钥<input v-model="serverKey" :disabled="locked" required autocomplete="off" placeholder="X25519 公钥（Base64）" /></label>
            <label class="wide">Rathole 引擎路径（可选）<input v-model="engine" :disabled="locked" placeholder="留空使用安装包内置引擎" /></label>
          </div>
          <p class="hint">默认使用内置 Rathole v0.5.0；自定义引擎仍须通过 SHA-256 校验。普通保存不写入 Token；仅主动选择加密保存才保留凭据。</p>
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

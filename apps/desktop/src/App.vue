<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { invoke } from '@tauri-apps/api/core'

type ManagedDevice={port:number;id:string}
type ManagedSync={id:string;name:string;revision:number;mappings:{id:string;protocol:string;local_port:number;bind_port:number;enabled:boolean;revision:number}[];last_seen_at:number;heartbeat_interval_seconds:number}
const managementPort=ref<number|null>(1431)
const managementName=ref('Windows 客户端')
const pairingCode=ref('')
const managedDevice=ref<ManagedDevice|null>(null)
const managedSync=ref<ManagedSync|null>(null)
const managementBusy=ref(false)
const managementReady=ref(false)
const managementBlocked=ref(false)
let managementPoll=false
let managementGeneration=0
async function refreshManagement(){
  if(!managementReady.value||managementBusy.value||managementPoll||!managedDevice.value)return
  const generation=managementGeneration
  managementPoll=true
  try{
    const result=await invoke<{observation:ManagedSync|null;error:string|null;blocked:boolean}>('management_snapshot')
    if(generation!==managementGeneration||managementBusy.value)return
    if(managedSync.value?.revision!==result.observation?.revision||managedSync.value?.id!==result.observation?.id)importConfirm.value=false
    managedSync.value=result.observation
    managementBlocked.value=result.blocked
    managementError.value=result.error||''
    if(result.error&&managementMessage.value==='配置元数据及管理心跳同步成功')managementMessage.value=''
  }catch{
    if(generation===managementGeneration){managedSync.value=null;managementError.value='管理状态读取失败'}
  }finally{managementPoll=false}
}
const managementMessage=ref('')
const managementError=ref('')
const forgetConfirm=ref(false)
const importConfirm=ref(false)
async function importManagedUdp(item:ManagedSync['mappings'][number]){
  const snapshot=managedSync.value
  if(!snapshot||!importConfirm.value||locked.value||managementBusy.value||managementBlocked.value||polling)return
  const revision=snapshot.revision
  managementGeneration++;managementBusy.value=true;busy.value=true;importConfirm.value=false
  managementError.value='';managementMessage.value=''
  try{
    const draft=await invoke<{protocol:Protocol;name:string;localPort:number}>('management_import_udp',{id:item.id,expectedRevision:revision,mappingRevision:item.revision,confirmed:true})
    if(running.value||serviceBusy.value)throw Error('隧道状态变化，未导入')
    // Do not reuse credentials, an endpoint or an engine from a different mapping.
    engine.value='';remote.value='';serverKey.value='';mappings.value=[{...draft,id:nextId++,token:''}]
    managementMessage.value='UDP 草稿已导入，请填写独立中转参数及授权 Token；未启动隧道'
  }catch(e){managementError.value=String(e);managedSync.value=null}
  finally{busy.value=false;managementBusy.value=false;void refresh();void refreshManagement()}
}
async function loadManagement(){
  managementBusy.value=true
  try{
    managedDevice.value=await invoke<ManagedDevice|null>('management_saved')
    if(managedDevice.value)managementPort.value=managedDevice.value.port
  }catch(e){managementError.value=String(e)}
  finally{managementBusy.value=false;managementReady.value=true;void refreshManagement()}
}
async function managementAction(action:'pair'|'sync'|'forget'){
  if(managementBusy.value||!managementReady.value)return
  managementGeneration++;managementBusy.value=true;importConfirm.value=false;managementError.value='';managementMessage.value=''
  try{
    if(action==='pair'){
      if(!Number.isInteger(managementPort.value)||Number(managementPort.value)<1024||Number(managementPort.value)>65535)throw Error('请输入 1024–65535 的管理端口')
      const code=pairingCode.value.trim();pairingCode.value=''
      managedDevice.value=await invoke<ManagedDevice>('management_enroll',{port:Number(managementPort.value),name:managementName.value.trim(),pairingCode:code})
      managementBlocked.value=false
      managementMessage.value='设备已配对，凭据已加密保存'
    }else if(action==='sync'){
      managedSync.value=null
      managedSync.value=await invoke<ManagedSync>('management_sync')
      managementMessage.value='配置元数据及管理心跳同步成功'
    }else{
      if(!forgetConfirm.value)return
      await invoke('management_forget')
      managedDevice.value=null;managedSync.value=null;managementBlocked.value=false;forgetConfirm.value=false;pairingCode.value=''
      managementMessage.value='本地管理凭据已移除；请在后台吊销旧设备'
    }
  }catch(e){managementError.value=String(e);managedSync.value=null}
  finally{managementBusy.value=false;void refreshManagement()}
}

type Protocol = 'tcp' | 'udp'
type Mapping = { id: number; protocol: Protocol; name: string; localPort: number | null; token: string }
type Profile = { engine: string; remote: string; serverKey: string; mappings: { protocol: Protocol; name: string; localPort: number }[] }
type StartRequest = Omit<Profile, 'mappings'> & { mappings: { protocol: Protocol; name: string; localPort: number; token: string }[] }
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
const provisionConfirm = ref(false)
const maintenanceConfirm = ref('')
async function maintainService(action: 'update' | 'unregister') {
  const name = watchedService.value
  if (!name || serviceName.value.trim() !== name || maintenanceConfirm.value !== name ||
      serviceSnapshot.value?.state !== 'stopped' || serviceBusy.value || busy.value) return
  if (action === 'update' && (running.value || engine.value.trim() ||
      mappings.value.some(m => !Number.isInteger(m.localPort) || Number(m.localPort) < 1 || Number(m.localPort) > 65535))) {
    serviceActionError.value = '请停止桌面隧道，清空自定义引擎路径并填写有效端口'; return
  }
  serviceBusy.value = true
  serviceGeneration++
  serviceActionError.value = ''
  serviceActionNotice.value = ''
  try {
    if (action === 'update') {
      await invoke('update_service_profile', { name, confirmation: maintenanceConfirm.value, request: {
        engine: '', remote: remote.value.trim(), serverKey: serverKey.value.trim(),
        mappings: mappings.value.map(m => ({ protocol: m.protocol, name: m.name.trim(), localPort: m.localPort, token: m.token }))
      } })
      serviceActionNotice.value = '配置已更新，服务保持禁用；检查后可设为手动启动'
    } else {
      await invoke('unregister_service', { name, confirmation: maintenanceConfirm.value })
      watchedService.value = ''
      serviceName.value = ''
      serviceActionNotice.value = '已注销 SCM 注册，受保护目录、凭据和历史流量仍保留'
    }
    maintenanceConfirm.value = ''
  } catch (e) {
    serviceActionError.value = '服务维护失败：' + String(e)
  } finally {
    serviceSnapshot.value = null
    serviceBusy.value = false
    void refreshService()
  }
}
async function provisionService() {
  if (serviceBusy.value || busy.value || running.value || !ready.value || !provisionConfirm.value) return
  if (engine.value.trim()) { serviceActionError.value = '后台服务只允许内置引擎，请清空自定义路径'; return }
  if (mappings.value.some(m => !Number.isInteger(m.localPort) || Number(m.localPort) < 1 || Number(m.localPort) > 65535)) {
    serviceActionError.value = '请填写有效本地端口'; return
  }
  serviceBusy.value = true
  serviceGeneration++
  serviceActionError.value = ''
  serviceActionNotice.value = ''
  try {
    const name = await invoke<string>('provision_service', { request: {
      engine: '', remote: remote.value.trim(), serverKey: serverKey.value.trim(),
      mappings: mappings.value.map(m => ({ protocol: m.protocol, name: m.name.trim(), localPort: m.localPort, token: m.token }))
    } })
    serviceName.value = name
    watchedService.value = name
    serviceSnapshot.value = null
    serviceActionNotice.value = '新服务已部署，默认停止、手动启动'
    provisionConfirm.value = false
  } catch (e) {
    serviceActionError.value = '部署失败：' + String(e)
  } finally {
    serviceBusy.value = false
    void refreshService()
  }
}
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
  maintenanceConfirm.value = ''
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
  maintenanceConfirm.value = ''
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
const mappings = ref<Mapping[]>([{ id: 1, protocol: 'tcp', name: 'web', localPort: 8080, token: '' }])
const status = ref<Status>({ state: 'stopped', detail: '正在获取进程状态', mappingCount: 0 })
const busy = ref(false)
const error = ref('')
const notice = ref('')
const portNotice = ref<Record<number, string>>({})
const ready = ref(false)
const running = computed(() => status.value.state === 'running')
const locked = computed(() => busy.value || running.value || !ready.value || serviceBusy.value)
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
onMounted(() => { void refresh(); void loadManagement(); timer = setInterval(() => { void refresh(); void refreshService(); void refreshManagement() }, 1200) })
onUnmounted(() => { if (timer) clearInterval(timer) })
function add() {
  if (locked.value || mappings.value.length >= 64) return
  mappings.value.push({ id: nextId++, protocol: 'tcp', name: '', localPort: 8080, token: '' })
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
        mappings: mappings.value.map(m => ({ protocol: m.protocol, name: m.name.trim(), localPort: Number(m.localPort) }))
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
    mappings: mappings.value.map(m => ({ protocol: m.protocol, name: m.name.trim(), localPort: Number(m.localPort), token: m.token }))
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
  if (mapping.protocol !== 'tcp') return
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
  if (!ready.value || busy.value || polling || serviceBusy.value) return
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
        mappings: mappings.value.map(m => ({ protocol: m.protocol, name: m.name.trim(), localPort: m.localPort, token: m.token }))
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
        <div class="section-title"><h2>管理设备配对</h2><span>V0.4 本机控制面预览</span></div>
        <p class="hint">仅 HTTP 127.0.0.1 本机管理服务；不会自动启动或修改现有隧道。配对后由 Rust 每30秒自动同步管理心跳与期望配置元数据，关闭窗口至托盘时仍继续。</p>
        <div v-if="!managedDevice" class="fields">
          <label>本机管理端口<input aria-label="本机管理端口" type="number" min="1024" max="65535" v-model.number="managementPort" :disabled="managementBusy||!managementReady"/></label>
          <label>设备名称<input aria-label="管理设备名称" v-model="managementName" maxlength="128" :disabled="managementBusy||!managementReady"/></label>
          <label class="wide">一次性配对码<input aria-label="管理配对码" type="password" autocomplete="off" v-model="pairingCode" :disabled="managementBusy||!managementReady"/></label>
        </div>
        <div class="profile-actions">
          <button v-if="!managedDevice" type="button" class="secondary" :disabled="managementBusy||!managementReady||!pairingCode" @click="managementAction('pair')">配对管理设备</button>
          <button v-if="managedDevice" type="button" class="secondary" :disabled="managementBusy||managementBlocked" @click="managementAction('sync')">同步管理状态</button>
          <label><input type="checkbox" aria-label="确认移除管理凭据" v-model="forgetConfirm" :disabled="managementBusy"/> 仅移除本机管理凭据，不代表服务器吊销</label>
          <button type="button" class="secondary" :disabled="managementBusy||!managementReady||!forgetConfirm" @click="managementAction('forget')">移除管理凭据</button>
        </div>
        <p v-if="managedDevice" class="hint">已配对 ID：{{ managedDevice.id }} · 127.0.0.1:{{ managedDevice.port }}</p>
        <p v-if="managedDevice" class="hint" data-testid="management-auto-state">{{ managementBlocked?'认证拒绝，自动同步已停止':managedSync?'自动同步已收到管理配置':managementError?'同步失败，等待重试':'等待自动同步' }}</p>
        <div v-if="managedSync" aria-live="polite">
          <p>管理配置版本：{{managedSync.revision}} · 期望映射：{{managedSync.mappings.length}} · 管理模式：idle（未应用隧道配置）</p>
          <p class="hint">最近心跳：{{new Date(managedSync.last_seen_at*1000).toLocaleString()}}；自动同步间隔约30秒（请求耗时另计）。不是实际隧道在线证明。</p>
          <label v-if="managedSync.mappings.some(m=>m.protocol==='udp'&&!m.enabled)"><input type="checkbox" aria-label="确认导入 UDP 草稿" v-model="importConfirm" :disabled="locked||managementBusy"/> 确认替换当前编辑表单并清空旧连接参数及 Token（不修改已保存配置或后台服务）</label>
          <div v-for="item in managedSync.mappings" :key="item.id"><p class="hint">{{item.protocol.toUpperCase()}} · 本地 {{item.local_port}} → 中转 {{item.bind_port}} · {{item.enabled?'期望启用':'草稿禁用'}}</p>
          <button v-if="item.protocol==='udp'&&!item.enabled" type="button" class="secondary" :disabled="locked||managementBusy||managementBlocked||!importConfirm" @click="importManagedUdp(item)">导入 UDP 草稿</button></div>
        </div>
        <p v-if="managementMessage" class="hint" role="status">{{managementMessage}}</p>
        <p v-if="managementError" class="error" role="alert">{{managementError}}</p>
      </section>
      <section>
        <div class="section-title"><h2>桌面隧道流量</h2><span>{{ traffic?.state === 'measured' ? '实际应用数据' : '未计量 / 未启动' }}</span></div>
        <div class="summary">
          <div><small>上传速度</small><strong class="protocol">{{ formatBytes(traffic?.uploadBytesPerSecond, true) }}</strong><span>累计 {{ formatBytes(traffic?.uploadBytes) }}</span></div>
          <div><small>下载速度</small><strong class="protocol">{{ formatBytes(traffic?.downloadBytesPerSecond, true) }}</strong><span>累计 {{ formatBytes(traffic?.downloadBytes) }}</span></div>
          <div><small>计量范围</small><strong class="protocol">本次会话</strong><span>不含加密及传输开销</span></div>
        </div>
        <p class="hint">以上为本次桌面会话；历史统计每 5 秒保存，正常停止时保存最终值。</p>
        <div class="summary">
          <div><small>历史累计上传</small><strong class="protocol">{{ formatBytes(trafficHistory?.saved?.uploadBytes) }}</strong><span>本机已保存</span></div>
          <div><small>历史累计下载</small><strong class="protocol">{{ formatBytes(trafficHistory?.saved?.downloadBytes) }}</strong><span>本机已保存</span></div>
          <div><small>最近保存</small><strong class="protocol">{{ trafficHistory?.saved ? new Date(trafficHistory.saved.savedAtMs).toLocaleTimeString() : '—' }}</strong><span>仅桌面模式</span></div>
        </div>
        <p v-if="running && mappings.some(m=>m.protocol==='udp')" class="hint">UDP 与 TCP 合并计量；UDP 每映射最多32来源、1200字节/包，固定包速率保护。</p>
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
        <div class="profile-actions">
          <label><input type="checkbox" aria-label="确认部署新服务" v-model="provisionConfirm" :disabled="serviceBusy" /> 使用下方映射配置创建新服务，允许系统级加密保存 Token</label>
          <button type="button" class="secondary" :disabled="locked || !provisionConfirm || mappings.some(m=>m.protocol!=='tcp')" @click="provisionService">一键部署新服务</button>
        </div>
        <p class="hint">需要以管理员身份运行客户端；创建全新服务，不覆盖旧配置。默认停止且手动启动。失败时保留受保护目录供检查。</p>
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
        <p v-else-if="serviceSnapshot?.state === 'running'" class="hint">流量快照不可用（权限不足、恢复中、尚未采样或计量器异常）。</p>
        <div v-if="serviceSnapshot?.history" class="summary">
          <div><small>服务历史累计上传</small><strong class="protocol">{{ formatBytes(serviceSnapshot.history.uploadBytes) }}</strong><span>已保存</span></div>
          <div><small>服务历史累计下载</small><strong class="protocol">{{ formatBytes(serviceSnapshot.history.downloadBytes) }}</strong><span>已保存</span></div>
          <div><small>最近保存</small><strong class="protocol">{{ new Date(serviceSnapshot.history.savedAtMs).toLocaleTimeString() }}</strong><span>独立于桌面历史</span></div>
        </div>
        <p v-else-if="serviceSnapshot" class="hint">服务历史暂无可读记录（未配置、未保存或权限不足）。</p>
        <p v-if="serviceSnapshot?.history" class="hint">已保存历史包含实际计量的 TCP/UDP 应用字节；不与会话流量重复相加，强制结束可能丢失未保存增量。</p>
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
        <div v-if="serviceSnapshot?.state === 'stopped'" class="fields">
          <label class="wide">维护确认：完整输入当前服务名称<input v-model="maintenanceConfirm" :disabled="serviceBusy" maxlength="51" autocomplete="off" :placeholder="watchedService" /></label>
        </div>
        <div v-if="serviceSnapshot?.state === 'stopped'" class="profile-actions">
          <button type="button" class="secondary" :disabled="serviceBusy || busy || running || serviceName.trim() !== watchedService || maintenanceConfirm !== watchedService || mappings.some(m=>m.protocol!=='tcp')" @click="maintainService('update')">使用下方表单更新服务配置</button>
          <button type="button" class="secondary" :disabled="serviceBusy || busy || serviceName.trim() !== watchedService || maintenanceConfirm !== watchedService" @click="maintainService('unregister')">注销服务注册</button>
        </div>
        <p v-if="serviceSnapshot?.state === 'stopped'" class="hint">更新将替换整套加密配置并保持禁用，需手动恢复启动方式；注销只删除服务注册，不删除配置或历史目录。不会读取或显示旧 Token。</p>
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
          </div><div class="port-actions"><label>协议 <select v-model="mapping.protocol" :disabled="locked" aria-label="映射协议" @change="delete portNotice[mapping.id]"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><button type="button" class="secondary" :disabled="busy || !ready || mapping.protocol!=='tcp'" @click="probe(mapping)">检测本地端口</button><span role="status">{{ mapping.protocol==='udp' ? 'UDP 不支持 TCP 端口探测' : (portNotice[mapping.id] || "未检测") }}</span></div></div>
          <p class="hint">端口检测只验证本地 TCP 可达性，不代表服务端认证或公网在线。目标地址固定为 127.0.0.1。UDP 须与中转映射协议一致，支持桌面及后台服务；每会话最多8个 UDP 映射。停止隧道后可编辑配置；域名由服务端分配。</p>
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

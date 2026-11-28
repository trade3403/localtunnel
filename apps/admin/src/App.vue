<script setup lang="ts">
import { computed, ref, reactive, onBeforeUnmount } from 'vue'
import { api, ApiError } from './api'

type Device = {id:string;name:string;enabled:boolean;revision:number}
type Node = {id:string;name:string;enabled:boolean;region:string;policy_mode:string;policy_revision:number;approved_capacity:number;reported_capacity:number|null;received_at:number|null;health:string;candidate_capacity:number;owner_mappings:number;owner_reserved_allocations:number}
const nodeHealthLabels:Record<string,string>={online:'在线',offline:'离线',disabled:'停用',unregistered:'未注册',revoked:'凭据已撤销',awaiting_heartbeat:'等待心跳'}
const nodePolicyLabels:Record<string,string>={active:'接收调度',draining:'排空中',maintenance:'维护中'}
const nodeHealthColor=(health:string)=>health==='online'?'green':health==='offline'||health==='revoked'?'red':'default'
const nodeTime=(time:number|null)=>time===null?'—':new Date(time*1000).toLocaleString('zh-CN')
type Domain = {id:string;hostname:string;verified_at:number|null;txt_name:string;txt_value:string|null}
type Mapping = {id:string;device_id:string;node_id:string;domain_id:string|null;protocol:string;local_host:string;local_port:number;bind_port:number;enabled:boolean;revision:number}
type Runtime = {request:{request_id:string;state:string;updated_at:number}|null;worker_recent:boolean}
type Entitlement = {tenant_id:string;plan_id:string;plan_code:string;plan_version:number;plan_name:string;revision:number;state:string;effective_state:string;expires_at:number|null;max_active_devices:number;max_retained_devices:number;max_mappings:number;max_bandwidth_bps:number|null;max_monthly_bytes:number|null;max_concurrent_connections:number|null;active_devices:number;retained_devices:number;mappings:number;bandwidth_reservations:number;reserved_bytes_per_second:number|null;month_utc:string;monthly_charged_bytes:number;reserved_connection_slots:number}
const commercial=ref<Entitlement|null>(null)
async function loadCommercial(){
  commercial.value=null
  const result=await get<{scope:string;commercial_enforcement:boolean;entitlement:Entitlement}>('/commercial/entitlement')
  if(result.scope!=='owner_inventory_only')throw Error('unexpected commercial scope')
  commercial.value=result.entitlement
}
const formatCount=(n:number|null)=>n===null?'不限额':n.toLocaleString('zh-CN')
const token = ref('')
const user = ref('')
const username = ref('')
const password = ref('')
const busy = ref(false)
const error = ref('')
const notice = ref('')
const page = ref('dashboard')
const devices = ref<Device[]>([])
const nodes = ref<Node[]>([])
const domains = ref<Domain[]>([])
const mappings = ref<Mapping[]>([])
type Resource = 'devices'|'nodes'|'domains'|'mappings'
const lists={devices,nodes,domains,mappings}
const more=reactive<Record<Resource,boolean>>({devices:false,nodes:false,domains:false,mappings:false})
const editDraft=ref<{id:string;revision:number;local_port:number;bind_port:number}|null>(null)
const pairing = ref('')
let pairTimer: ReturnType<typeof setTimeout>|undefined
const domainName = ref('')
const selectedMapping = ref<Mapping|null>(null)
const runtime = ref<Runtime|null>(null)
type TrafficObservation={request_id:string;mapping_revision:number;requests:number;request_bytes:number;response_bytes:number;sampled_at:number;sampling_state:string}
const traffic=ref<TrafficObservation[]>([])
type AuditEvent={seq:number;event:string;resource_id:string;revision:number|null;request_id:string|null;state:string|null;occurred_at:number}
const auditEvents=ref<AuditEvent[]>([])
const auditBefore=ref<number|null>(null)
async function loadAudit(append=false){
  if(append&&auditBefore.value===null)return
  const result=await get<{events:AuditEvent[];next_before:number|null}>('/audit'+(append?'?before='+auditBefore.value:''))
  auditEvents.value=append?[...auditEvents.value,...result.events]:result.events
  auditBefore.value=result.next_before
}
const auditLabels:Record<string,string>={'commercial.account_created':'商业账户创建','commercial.entitlement_assigned':'套餐授权变更','session.created':'会话创建','session.replaced':'会话替换','session.removed':'会话移除','pairing.issued':'配对码签发','pairing.replaced':'配对码替换','device.created':'设备创建','device.authorization_changed':'设备授权变更','domain.created':'域名创建','domain.proof_changed':'域名证明变更','domain.deleted':'域名删除','mapping.created':'映射创建','mapping.updated':'映射更新','mapping.deleted':'映射删除','runtime.transition':'执行状态变更'}
async function readTraffic(id:string){
  traffic.value=(await get<{observations:TrafficObservation[]}>('/mappings/'+id+'/traffic')).observations
}
const deviceStatus = ref<Record<string,unknown>|null>(null)
const create = reactive({device_id:'',node_id:'',domain_id:'',protocol:'http',local_port:8080,bind_port:20000})
type AllocationOverview={id:string;mapping_id:string;node_id:string;node_name:string;generation:number;node_generation:number;bind_port:number;state:string;protocol:string|null;local_port:number|null;grant_kind:string|null;expires_at:number|null;authorization_state:string;failure_reason:string|null;failure_at:number|null;fenced_at:number|null;cleanup_at:number|null;reclaimed_at:number|null;retired_at:number|null;auto_state:string|null;source_id:string|null;successor_id:string|null;lineage_epoch:number;monthly_bytes:number|null;connection_slots:number|null;rate_bytes_per_second:number|null;month_utc:string|null}
const allocations=ref<AllocationOverview[]>([])
const allocationAfter=ref<string|null>(null)
const allocationLabels:Record<string,string>={retired:'已退役',fenced:'已隔离',cancelled:'已取消',not_issued:'未签发许可',revoked:'许可已撤销',expired:'许可已到期',claimed:'已领取许可',pending_claim:'等待领取',issued:'已签发许可'}
const failureLabels:Record<string,string>={node_disabled:'节点停用',identity_unavailable:'节点身份不可用',heartbeat_stale:'心跳失效'}
async function loadAllocations(append=false){
  if(append&&!allocationAfter.value)return
  const result=await get<{scope:string;executable:boolean;allocations:AllocationOverview[];next_after:string|null}>('/allocations'+(append?'?after='+encodeURIComponent(allocationAfter.value!):''))
  if(result.scope!=='owner_allocation_observations_only'||result.executable!==false)throw Error('unexpected allocation scope')
  allocations.value=append?[...allocations.value,...result.allocations]:result.allocations
  allocationAfter.value=result.next_after
}
const nav = [{key:'dashboard',label:'仪表盘'},{key:'devices',label:'设备管理'},{key:'mappings',label:'映射管理'},{key:'domains',label:'域名管理'},{key:'nodes',label:'节点管理'},{key:'allocations',label:'分配与切换'},{key:'audit',label:'操作审计'},{key:'commercial',label:'套餐与额度'}]
const title = computed(() => nav.find(n=>n.key===page.value)?.label)
const labels:Record<string,string> = {queued:'等待执行器',starting:'启动中',running:'已应用（执行器报告）',stopping:'停止中',stopped:'已停止',failed_or_unknown:'失败或未知'}
function clearPair(){pairing.value='';if(pairTimer) clearTimeout(pairTimer)}
function reset(){
  auditEvents.value=[];auditBefore.value=null;commercial.value=null;allocations.value=[];allocationAfter.value=null
  token.value='';user.value='';password.value='';devices.value=[];nodes.value=[];domains.value=[];mappings.value=[];
  selectedMapping.value=null;runtime.value=null;traffic.value=[];deviceStatus.value=null;clearPair();notice.value='';page.value='dashboard'
  Object.assign(create,{device_id:'',node_id:'',domain_id:'',protocol:'http',local_port:8080,bind_port:20000})
  domainName.value='';editDraft.value=null
  for(const k of Object.keys(more) as Resource[])more[k]=false
}
async function run(fn:()=>Promise<void>){
  if(busy.value)return
  busy.value=true;error.value='';notice.value=''
  try{await fn()}catch(e){
    if(e instanceof ApiError && e.status===401 && token.value) reset()
    error.value=e instanceof ApiError?e.message:'管理服务连接失败，请检查本地服务'
  }finally{busy.value=false}
}
async function get<T>(path:string){return api<T>(path,token.value)}
async function send<T>(path:string,method:string,body?:unknown){return api<T>(path,token.value,method,body)}
async function refresh(){
  if(page.value==='allocations'){await loadAllocations();return}
  if(page.value==='audit'){await loadAudit();return}
  if(page.value==='commercial'){await loadCommercial();return}
  const [d,n,h,m]=await Promise.all([get<Device[]>('/devices'),get<Node[]>('/nodes/overview'),get<Domain[]>('/domains'),get<Mapping[]>('/mappings')])
  devices.value=d;nodes.value=n;domains.value=h;mappings.value=m
  more.devices=d.length===100;more.nodes=n.length===100;more.domains=h.length===100;more.mappings=m.length===100
  if(selectedMapping.value){
    selectedMapping.value=m.find(x=>x.id===selectedMapping.value?.id)||null
    runtime.value=selectedMapping.value?await get<Runtime>('/mappings/'+selectedMapping.value.id+'/runtime'):null
    if(selectedMapping.value)await readTraffic(selectedMapping.value.id);else traffic.value=[]
  }
}
async function loadMore(key:Resource){await run(async()=>{
  const rows=lists[key].value
  if(!more[key]||!rows.length)return
  const next=await get<(Device|Node|Domain|Mapping)[]>('/'+(key==='nodes'?'nodes/overview':key)+'?after='+encodeURIComponent(rows[rows.length-1].id))
  // Append only server-ordered records beyond the current cursor.
  // Avoid duplicates if a refresh/retry occurs.
  if(key==='devices')devices.value.push(...next as Device[])
  else if(key==='nodes')nodes.value.push(...next as Node[])
  else if(key==='domains')domains.value.push(...next as Domain[])
  else mappings.value.push(...next as Mapping[])
  more[key]=next.length===100
})}
async function login(){await run(async()=>{
  const s=await api<{access_token:string}>('/auth/login','','POST',{username:username.value,password:password.value})
  password.value='';token.value=s.access_token
  try{user.value=(await get<{username:string}>('/auth/me')).username;await refresh()}catch(e){reset();throw e}
})}
async function logout(){await run(async()=>{try{await send('/auth/logout','POST')}finally{reset()}})}
function go(key:string){if(busy.value)return;page.value=key;clearPair();deviceStatus.value=null;selectedMapping.value=null;runtime.value=null;traffic.value=[];editDraft.value=null;error.value='';notice.value='';auditEvents.value=[];auditBefore.value=null;commercial.value=null;if(key==='audit')void run(()=>loadAudit());if(key==='commercial')void run(loadCommercial);allocations.value=[];allocationAfter.value=null;if(key==='allocations')void run(()=>loadAllocations())}
async function issue(){await run(async()=>{clearPair();const p=await send<{pairing_code:string;expires_in:number}>('/devices/pairing-code','POST');pairing.value=p.pairing_code;pairTimer=setTimeout(clearPair,p.expires_in*1000)})}
async function revoke(d:Device){await run(async()=>{await send('/devices/'+d.id+'/revoke','POST');await refresh();deviceStatus.value=null;notice.value='设备凭据已吊销'})}
async function inspectDevice(d:Device){await run(async()=>{deviceStatus.value=await get('/devices/'+d.id+'/status')})}
async function addDomain(){await run(async()=>{await send('/domains','POST',{hostname:domainName.value});domainName.value='';await refresh();notice.value='域名草稿已创建'})}
async function verifyDomain(d:Domain){await run(async()=>{await send('/domains/verify','POST',{domain_id:d.id});await refresh();notice.value='DNS TXT 验证成功'})}
async function rotate(d:Domain){await run(async()=>{await send('/domains/'+d.id+'/challenge','POST');await refresh();notice.value='验证挑战已轮换'})}
async function removeDomain(d:Domain){await run(async()=>{
  await send('/domains/'+d.id,'DELETE')
  if(create.domain_id===d.id)create.domain_id=''
  await refresh();notice.value='域名已删除'
})}
function editMapping(m:Mapping){editDraft.value={id:m.id,revision:m.revision,local_port:m.local_port,bind_port:m.bind_port}}
async function saveMapping(){await run(async()=>{
  const d=editDraft.value;if(!d)return
  await send('/mappings/'+d.id,'PATCH',{expected_revision:d.revision,local_port:d.local_port,bind_port:d.bind_port})
  editDraft.value=null;await refresh();notice.value='映射已更新'
})}
async function removeMapping(m:Mapping){await run(async()=>{
  await send('/mappings/'+m.id+'?expected_revision='+m.revision,'DELETE')
  if(editDraft.value?.id===m.id)editDraft.value=null
  await refresh();notice.value='映射已删除'
})}
async function addMapping(){await run(async()=>{
  await send('/mappings','POST',{...create,domain_id:['http','https'].includes(create.protocol)?create.domain_id:null})
  await refresh();notice.value='禁用映射草稿已创建'
})}
async function inspectMapping(m:Mapping){await run(async()=>{selectedMapping.value=m;runtime.value=null;traffic.value=[];runtime.value=await get('/mappings/'+m.id+'/runtime');await readTraffic(m.id)})}
async function startMapping(){await run(async()=>{
  const m=selectedMapping.value;if(!m)return
  await send('/mappings/'+m.id+(m.protocol==='udp'?'/udp-start':m.protocol==='tcp'?'/tcp-start':'/start'),'POST',{expected_revision:m.revision});runtime.value=await get('/mappings/'+m.id+'/runtime');notice.value='启动请求已提交，等待本地执行器'
})}
async function stopMapping(){await run(async()=>{
  const m=selectedMapping.value,r=runtime.value?.request;if(!m||!r)return
  await send('/mappings/'+m.id+'/stop','POST',{request_id:r.request_id});runtime.value=await get('/mappings/'+m.id+'/runtime');notice.value='停止请求已提交'
})}
const canStart=computed(()=>selectedMapping.value && !selectedMapping.value.enabled && ['http','https','tcp','udp'].includes(selectedMapping.value.protocol) && runtime.value!==null && (!runtime.value.request||runtime.value.request.state==='stopped'||(runtime.value.request.state==='queued'&&runtime.value.request.updated_at<Math.floor(Date.now()/1000)-120)))
const canStop=computed(()=>runtime.value?.request && ['queued','starting','running','stopping'].includes(runtime.value.request.state))
function time(v:number|null){return v?new Date(v*1000).toLocaleString('zh-CN'):'未验证'}
function nameOf<T extends {id:string}>(rows:T[],id:string|null,field:keyof T){return rows.find(x=>x.id===id)?.[field]||id||'—'}
onBeforeUnmount(clearPair)
</script>
<template>
  <main v-if="!user" class="login">
    <a-card class="login-card" :bordered="false">
      <div class="brand"><span class="mark">LT</span> LocalTunnel</div>
      <h1>管理后台登录</h1><p class="muted">安全连接 · 本地管理预览</p>
      <a-alert v-if="error" type="error" :message="error" show-icon/>
      <form @submit.prevent="login">
        <label for="username">管理员账号</label><a-input id="username" v-model:value="username" autocomplete="username" required/>
        <label for="password">密码</label><a-input-password id="password" v-model:value="password" autocomplete="current-password" required/>
        <a-button type="primary" html-type="submit" aria-label="登录" block :loading="busy">登录</a-button>
      </form>
      <p class="muted small">无默认账号。由本地操作员初始化管理员。刷新页面后需要重新登录。</p>
    </a-card>
  </main>
  <a-layout v-else class="shell">
    <a-layout-sider :width="220" theme="dark" class="sidebar">
      <div class="brand"><span class="mark">LT</span> LocalTunnel</div>
      <p class="nav-caption">控制面 · V0.4</p>
      <a-menu theme="dark" mode="inline" :selected-keys="[page]" @click="({key})=>go(String(key))">
        <a-menu-item v-for="n in nav" :key="n.key" :disabled="busy">{{n.label}}</a-menu-item>
      </a-menu>
      <p class="sidebar-note">仅本机回环预览<br>未开放公网管理</p>
    </a-layout-sider>
    <a-layout>
      <a-layout-header class="top"><span>控制台 / {{title}}</span><a-space><span>{{user}}</span><a-button :disabled="busy" @click="logout">退出登录</a-button></a-space></a-layout-header>
      <a-layout-content class="content">
        <div class="heading"><div><h1>{{title}}</h1><p class="muted">真实管理 API · 每次读取最多 100 条记录</p></div><a-button :loading="busy" @click="run(refresh)">刷新数据</a-button></div>
        <a-alert type="info" show-icon message="管理预览：映射草稿默认禁用，启动请求需本地执行器领取；设备心跳不等于真实隧道在线。"/>
        <a-alert v-if="error" type="error" show-icon :message="error"/>
        <a-alert v-if="notice" type="success" show-icon :message="notice"/>
        <template v-if="page==='dashboard'">
          <div class="metrics"><a-card v-for="s in [{label:'设备（已加载）',value:devices.length},{label:'映射草稿（已加载）',value:mappings.length},{label:'域名（已加载）',value:domains.length},{label:'节点（已加载）',value:nodes.length}]" :key="s.label"><a-statistic :title="s.label" :value="s.value"/></a-card></div>
          <a-card title="管理操作"><a-space wrap><a-button v-for="n in nav.slice(1)" :key="n.key" @click="go(n.key)">{{n.label}}</a-button></a-space><p class="muted">数据来自当前管理员已加载的可见记录，不是全局统计。刷新会重新读取第一页。</p></a-card>
        </template>
        <template v-if="page==='commercial'">
          <a-alert type="info" show-icon message="仅显示当前租户的套餐和额度；套餐发布、账户创建与授权变更由可信本地操作员执行。"/>
          <a-card v-if="commercial" title="当前套餐" data-testid="commercial-entitlement">
            <a-descriptions bordered :column="2" size="small">
              <a-descriptions-item label="套餐名称">{{commercial.plan_name}}</a-descriptions-item>
              <a-descriptions-item label="套餐版本">{{commercial.plan_code}} / {{commercial.plan_version}}</a-descriptions-item>
              <a-descriptions-item label="有效状态"><a-tag :color="commercial.effective_state==='active'?'green':'red'">{{({active:'有效',suspended:'已暂停',expired:'已过期'} as Record<string,string>)[commercial.effective_state]||commercial.effective_state}}</a-tag></a-descriptions-item>
              <a-descriptions-item label="到期时间">{{commercial.expires_at===null?'无固定到期时间':time(commercial.expires_at)}}</a-descriptions-item>
              <a-descriptions-item label="授权版本">{{commercial.revision}}</a-descriptions-item>
              <a-descriptions-item label="租户 ID">{{commercial.tenant_id}}</a-descriptions-item>
            </a-descriptions>
          </a-card>
          <a-card v-if="commercial" title="额度与使用情况" data-testid="commercial-usage">
            <a-descriptions bordered :column="1" size="small">
              <a-descriptions-item label="启用设备">{{formatCount(commercial.active_devices)}} / {{formatCount(commercial.max_active_devices)}}</a-descriptions-item>
              <a-descriptions-item label="保留设备">{{formatCount(commercial.retained_devices)}} / {{formatCount(commercial.max_retained_devices)}}</a-descriptions-item>
              <a-descriptions-item label="映射">{{formatCount(commercial.mappings)}} / {{formatCount(commercial.max_mappings)}}</a-descriptions-item>
              <a-descriptions-item label="套餐带宽上限 (bit/s)">{{formatCount(commercial.max_bandwidth_bps)}}</a-descriptions-item>
              <a-descriptions-item label="每方向预留带宽 (B/s)">{{commercial.reserved_bytes_per_second===null?'存在不限额预留':formatCount(commercial.reserved_bytes_per_second)}}</a-descriptions-item>
              <a-descriptions-item label="运行预算预留数">{{formatCount(commercial.bandwidth_reservations)}}</a-descriptions-item>
              <a-descriptions-item label="月度预扣字节 (UTC)">{{commercial.month_utc}}：{{formatCount(commercial.monthly_charged_bytes)}} / {{formatCount(commercial.max_monthly_bytes)}}</a-descriptions-item>
              <a-descriptions-item label="并发预留槽位">{{formatCount(commercial.reserved_connection_slots)}} / {{formatCount(commercial.max_concurrent_connections)}}</a-descriptions-item>
            </a-descriptions>
            <p class="muted">带宽为同库固定预算预留，不是实时速率；月度预扣不等于实际送达或账单，不限额流量未计入。并发槽位包含受控 TCP 后端流、UDP 来源及未确认释放的槽位。当前并非生产级计费或跨节点额度系统。</p>
          </a-card>
          <a-card v-if="!commercial&&!busy&&!error"><p>暂无套餐数据，请刷新重试。</p></a-card>
        </template>
        <template v-if="page==='devices'">
          <a-card title="设备列表"><template #extra><a-button type="primary" :loading="busy" @click="issue">生成配对码</a-button></template>
            <a-alert v-if="pairing" type="warning" message="一次性配对码（10 分钟有效，请仅交给可信设备）"><template #description><code class="wrap-code" data-testid="pairing">{{pairing}}</code><a-button size="small" @click="clearPair">隐藏</a-button></template></a-alert>
            <a-table :data-source="devices" :pagination="{pageSize:10}" row-key="id" :scroll="{x:650}">
              <a-table-column title="设备名称" data-index="name"/><a-table-column title="版本" data-index="revision"/>
              <a-table-column title="凭据状态"><template #default="{record}"><a-tag :color="record.enabled?'green':'default'">{{record.enabled?'已启用':'已吊销'}}</a-tag></template></a-table-column>
              <a-table-column title="操作"><template #default="{record}"><a-space><a-button size="small" :disabled="busy" @click="inspectDevice(record)">管理状态</a-button><a-popconfirm title="永久吊销该设备凭据？" @confirm="revoke(record)"><a-button danger size="small" :disabled="busy||!record.enabled">吊销</a-button></a-popconfirm></a-space></template></a-table-column>
            </a-table>
            <div class="cursor-footer"><span data-testid="devices-count">已加载 {{devices.length}} 条</span><a-button v-if="more.devices" :disabled="busy" @click="loadMore('devices')" data-testid="devices-more">加载更多</a-button></div>
            <a-card v-if="deviceStatus" size="small" title="设备心跳（自报）"><p>管理在线：{{deviceStatus.management_online?'是':'否'}}</p><p>期望版本：{{deviceStatus.desired_revision}} · 自报版本：{{deviceStatus.reported_revision??'—'}}</p><p>自报状态：{{deviceStatus.reported_state??'—'}}</p></a-card>
          </a-card>
        </template>
        <template v-if="page==='allocations'">
          <div class="metrics">
            <a-card><a-statistic title="已加载分配" :value="allocations.length"/></a-card>
            <a-card><a-statistic title="保留分配（已加载）" :value="allocations.filter(a=>a.state==='reserved').length"/></a-card>
            <a-card><a-statistic title="历史故障观察（已加载）" :value="allocations.filter(a=>a.failure_at!==null).length"/></a-card>
            <a-card><a-statistic title="已有替代分配（已加载）" :value="allocations.filter(a=>a.successor_id!==null).length"/></a-card>
          </div>
          <a-card title="分配与切换记录" data-testid="allocation-overview">
            <p class="muted">仅显示当前租户。许可签发、领取、隔离及回收是控制面记录，不证明隧道正在运行。历史记录保留，已退役不代表月流量退还。</p>
            <a-table :data-source="allocations" row-key="id" :pagination="{pageSize:10}" :scroll="{x:1400}">
              <a-table-column title="分配 ID"><template #default="{record}"><div class="wrap-code">{{record.id}}</div><div class="small muted">代际 {{record.generation}} · 节点代际 {{record.node_generation}}</div></template></a-table-column>
              <a-table-column title="节点 / 端口"><template #default="{record}">{{record.node_name}}<div class="small">{{record.protocol?.toUpperCase()||'—'}} {{record.local_port??'—'}} → {{record.bind_port}}</div></template></a-table-column>
              <a-table-column title="许可状态"><template #default="{record}"><a-tag>{{allocationLabels[record.authorization_state]||'未知'}}</a-tag><div class="small muted">到期 {{nodeTime(record.expires_at)}}</div></template></a-table-column>
              <a-table-column title="故障观察"><template #default="{record}">{{record.failure_reason?(failureLabels[record.failure_reason]||'未知'):'—'}}<div class="small muted">{{nodeTime(record.failure_at)}}</div></template></a-table-column>
              <a-table-column title="隔离与回收"><template #default="{record}"><div>隔离 {{nodeTime(record.fenced_at)}}</div><div>清理 {{nodeTime(record.cleanup_at)}}</div><div>回收 {{nodeTime(record.reclaimed_at)}}</div><div>退役 {{nodeTime(record.retired_at)}}</div></template></a-table-column>
              <a-table-column title="切换链路"><template #default="{record}"><div>链路代际 {{record.lineage_epoch}}</div><div class="small">自动预留 {{record.auto_state==='enabled'?'已授权':record.auto_state==='cancelled'?'已撤销':'未授权'}}</div><div v-if="record.source_id" class="wrap-code">来源 {{record.source_id}}</div><div v-if="record.successor_id" class="wrap-code">替代 {{record.successor_id}}</div></template></a-table-column>
              <a-table-column title="有限预算"><template #default="{record}"><template v-if="record.monthly_bytes!==null"><div>{{record.monthly_bytes}} B / {{record.month_utc}}</div><div>{{record.rate_bytes_per_second}} B/s · {{record.connection_slots}} 槽</div></template><span v-else>—</span></template></a-table-column>
            </a-table>
            <div class="cursor-footer"><span data-testid="allocations-count">已加载 {{allocations.length}} 条</span><a-button v-if="allocationAfter!==null" :disabled="busy" @click="run(()=>loadAllocations(true))">加载更多</a-button></div>
          </a-card>
        </template>
        <template v-if="page==='nodes'">
          <div class="metrics" data-testid="node-overview-metrics">
            <a-card><a-statistic title="已加载节点" :value="nodes.length"/></a-card>
            <a-card><a-statistic title="在线（已加载）" :value="nodes.filter(n=>n.health==='online').length"/></a-card>
            <a-card><a-statistic title="排空 / 维护（已加载）" :value="nodes.filter(n=>n.policy_mode!=='active').length"/></a-card>
            <a-card><a-statistic title="我的保留分配（已加载节点）" :value="nodes.reduce((sum,n)=>sum+n.owner_reserved_allocations,0)"/></a-card>
          </div>
          <a-card title="共享节点监控">
            <p class="muted">只读快照；本地操作员维护节点及调度策略。在线表示当前凭据心跳新鲜，不代表隧道可用。候选容量是批准与上报容量的较小值（仅在线且接收调度时），不是可用余量。</p>
            <a-table :data-source="nodes" row-key="id" :pagination="{pageSize:10}" :scroll="{x:1160}" data-testid="node-overview">
              <a-table-column title="节点"><template #default="{record}"><strong>{{record.name}}</strong><div class="muted wrap-code">{{record.id}}</div></template></a-table-column>
              <a-table-column title="地区" data-index="region"/>
              <a-table-column title="健康状态"><template #default="{record}"><a-tag :color="nodeHealthColor(record.health)">{{nodeHealthLabels[record.health]||'未知'}}</a-tag></template></a-table-column>
              <a-table-column title="调度策略"><template #default="{record}"><a-tag>{{nodePolicyLabels[record.policy_mode]||'未知'}}</a-tag><div class="small muted">版本 {{record.policy_revision}}</div></template></a-table-column>
              <a-table-column title="批准 / 上报"><template #default="{record}">{{record.approved_capacity}} / {{record.reported_capacity??'—'}}</template></a-table-column>
              <a-table-column title="候选容量" data-index="candidate_capacity"/>
              <a-table-column title="我的映射 / 保留分配"><template #default="{record}">{{record.owner_mappings}} / {{record.owner_reserved_allocations}}</template></a-table-column>
              <a-table-column title="最近心跳"><template #default="{record}">{{nodeTime(record.received_at)}}</template></a-table-column>
            </a-table>
            <div class="cursor-footer"><span data-testid="nodes-count">已加载 {{nodes.length}} 条</span><a-button v-if="more.nodes" :disabled="busy" @click="loadMore('nodes')" data-testid="nodes-more">加载更多</a-button></div>
          </a-card>
        </template>
        <template v-if="page==='domains'">
          <a-card title="添加域名"><form class="inline-form" @submit.prevent="addDomain"><a-input v-model:value="domainName" aria-label="域名" placeholder="web.example.com" required/><a-button type="primary" html-type="submit" :loading="busy">添加域名</a-button></form></a-card>
          <a-card title="域名列表"><a-table :data-source="domains" row-key="id" :pagination="{pageSize:10}" :scroll="{x:800}">
            <a-table-column title="域名" data-index="hostname"/><a-table-column title="最近验证"><template #default="{record}">{{time(record.verified_at)}}</template></a-table-column>
            <a-table-column title="TXT 证明"><template #default="{record}"><div class="wrap-code">{{record.txt_name}}<br>{{record.txt_value||'请轮换挑战'}}</div></template></a-table-column>
            <a-table-column title="操作"><template #default="{record}"><a-space><a-button size="small" :disabled="busy" @click="verifyDomain(record)">验证</a-button><a-popconfirm title="轮换会使旧验证失效，继续？" @confirm="rotate(record)"><a-button size="small" :disabled="busy">轮换</a-button></a-popconfirm><a-popconfirm ok-text="确认删除" cancel-text="取消" title="删除该域名？存在映射引用时服务端会拒绝。" @confirm="removeDomain(record)"><a-button danger size="small" aria-label="删除域名" :disabled="busy">删除</a-button></a-popconfirm></a-space></template></a-table-column>
          </a-table><div class="cursor-footer"><span data-testid="domains-count">已加载 {{domains.length}} 条</span><a-button v-if="more.domains" :disabled="busy" @click="loadMore('domains')" data-testid="domains-more">加载更多</a-button></div></a-card>
        </template>
        <template v-if="page==='audit'">
          <a-card title="所属资源的已提交状态变更">
            <p class="muted">记录会话、配对、设备、域名、映射及运行状态变更；不是全部访问、失败尝试或操作者身份审计。不记录密码、令牌、请求正文。</p>
            <a-table data-testid="audit-table" :data-source="auditEvents" row-key="seq" size="small" :pagination="{pageSize:10}" :scroll="{x:800}">
              <a-table-column title="时间"><template #default="{record}">{{time(record.occurred_at)}}</template></a-table-column>
              <a-table-column title="事件"><template #default="{record}">{{auditLabels[record.event]||record.event}}</template></a-table-column>
              <a-table-column title="资源 ID" data-index="resource_id"/>
              <a-table-column title="版本" data-index="revision"/>
              <a-table-column title="状态" data-index="state"/>
              <a-table-column title="请求 ID" data-index="request_id"/>
            </a-table>
            <div class="cursor-footer"><span>已加载 {{auditEvents.length}} 条</span><a-button v-if="auditBefore!==null" :disabled="busy" @click="run(()=>loadAudit(true))">加载更多</a-button></div>
          </a-card>
        </template>
        <template v-if="page==='mappings'">
          <a-card title="新建映射草稿"><p class="muted">设备、节点与域名选择来自已加载列表，可在对应页面加载更多。</p><form class="mapping-form" @submit.prevent="addMapping">
            <label>设备<a-select data-testid="mapping-device" v-model:value="create.device_id" aria-label="设备" :options="devices.filter(d=>d.enabled).map(d=>({value:d.id,label:d.name}))"/></label>
            <label>节点<a-select data-testid="mapping-node" v-model:value="create.node_id" aria-label="节点" :options="nodes.filter(n=>n.enabled).map(n=>({value:n.id,label:n.name}))"/></label>
            <label>协议<a-select data-testid="mapping-protocol" v-model:value="create.protocol" aria-label="协议" :options="['http','https','tcp','udp'].map(v=>({value:v,label:v.toUpperCase()}))"/></label>
            <label v-if="['http','https'].includes(create.protocol)">域名<a-select data-testid="mapping-domain" v-model:value="create.domain_id" aria-label="映射域名" :options="domains.map(d=>({value:d.id,label:d.hostname}))"/></label>
            <label>本地端口<a-input-number v-model:value="create.local_port" :min="1" :max="65535"/></label>
            <label>中转端口<a-input-number v-model:value="create.bind_port" :min="20000" :max="29999"/></label>
            <a-button type="primary" html-type="submit" :loading="busy" :disabled="!create.device_id||!create.node_id||(['http','https'].includes(create.protocol)&&!create.domain_id)">创建草稿</a-button>
          </form></a-card>
          <a-card title="映射列表"><a-table :data-source="mappings" row-key="id" :pagination="{pageSize:10}" :scroll="{x:750}">
            <a-table-column title="协议" data-index="protocol"/><a-table-column title="域名"><template #default="{record}">{{nameOf(domains,record.domain_id,'hostname')}}</template></a-table-column>
            <a-table-column title="本地端口" data-index="local_port"/><a-table-column title="中转端口" data-index="bind_port"/><a-table-column title="版本" data-index="revision"/>
            <a-table-column title="操作"><template #default="{record}"><a-space><a-button :disabled="busy" size="small" @click="inspectMapping(record)">运行详情</a-button><a-button size="small" aria-label="编辑映射" :disabled="busy||record.enabled" @click="editMapping(record)">编辑</a-button><a-popconfirm ok-text="确认删除" cancel-text="取消" title="删除该映射草稿？未停止的运行请求会被拒绝。" @confirm="removeMapping(record)"><a-button danger size="small" aria-label="删除映射" :disabled="busy||record.enabled">删除</a-button></a-popconfirm></a-space></template></a-table-column>
          </a-table>
          <div class="cursor-footer"><span data-testid="mappings-count">已加载 {{mappings.length}} 条</span><a-button v-if="more.mappings" :disabled="busy" @click="loadMore('mappings')" data-testid="mappings-more">加载更多</a-button></div>
          <a-card v-if="editDraft" title="编辑映射端口" size="small">
            <p class="muted">当前编辑版本 {{editDraft.revision}}；设备、节点、域名和协议不可修改。运行中或未知状态由服务端拒绝。</p>
            <form class="mapping-form" @submit.prevent="saveMapping">
              <label>本地端口<a-input-number id="edit-local-port" v-model:value="editDraft.local_port" :min="1" :max="65535"/></label>
              <label>中转端口<a-input-number id="edit-bind-port" v-model:value="editDraft.bind_port" :min="20000" :max="29999"/></label>
              <a-space><a-button type="primary" html-type="submit" :loading="busy">保存端口</a-button><a-button aria-label="取消编辑" :disabled="busy" @click="editDraft=null">取消</a-button></a-space>
            </form>
          </a-card>
          <a-card v-if="selectedMapping" title="运行请求详情" size="small"><p>{{selectedMapping.id}}</p><p data-testid="runtime-state">{{runtime?labels[runtime.request?.state||'']||'尚无请求':'查询中'}}</p><p v-if="selectedMapping.protocol==='udp'" class="muted">UDP 仅限可信操作员预配置的本机回显预览；请求启动不代表实际运行或公网可达。</p><p v-if="selectedMapping.protocol==='tcp'" class="muted">TCP 仅限可信操作员预配置的本机回显预览；请求启动不代表实际运行或公网可达。</p><p class="muted">执行器最近更新：{{runtime?.worker_recent?'是':'否'}}；不是实时业务探测。</p><a-space><a-button type="primary" :disabled="busy||!canStart" @click="startMapping">请求启动</a-button><a-button danger :disabled="busy||!canStop" @click="stopMapping">请求停止</a-button><a-button :disabled="busy" @click="inspectMapping(selectedMapping)">刷新状态</a-button></a-space>
            <a-divider/>
            <h3>网关流量观测</h3><p v-if="selectedMapping.protocol==='udp'" class="muted">UDP 暂无网关流量统计；不显示虚构计费数据。</p><p v-if="selectedMapping.protocol==='tcp'" class="muted">TCP 暂无网关流量统计；不显示虚构计费数据。</p><p class="muted">已完成的 HTTP/HTTPS 请求长度与响应发送字节，含业务探测，非加密链路总量或计费；最多最近50次运行。</p>
            <p v-if="!traffic.length" data-testid="traffic-empty">暂无流量观测</p>
            <a-table v-else data-testid="traffic-table" :data-source="traffic" row-key="request_id" size="small" :pagination="{pageSize:5}" :scroll="{x:600}">
              <a-table-column title="请求数" data-index="requests"/>
              <a-table-column title="请求字节" data-index="request_bytes"/>
              <a-table-column title="响应字节" data-index="response_bytes"/>
              <a-table-column title="采样时间"><template #default="{record}">{{time(record.sampled_at)}}</template></a-table-column>
              <a-table-column title="采样状态"><template #default="{record}">{{({sampled:'已采样',partial:'停止时部分观测',unavailable:'采样不可用'})[record.sampling_state]||record.sampling_state}}</template></a-table-column>
            </a-table>
            <p class="muted">异常退出可能只保留上次采样；刷新状态更新观测。</p>
          </a-card></a-card>
        </template>
      </a-layout-content>
    </a-layout>
  </a-layout>
</template>

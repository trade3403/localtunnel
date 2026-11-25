<script setup lang="ts">
import { computed, ref, reactive, onBeforeUnmount } from 'vue'
import { api, ApiError } from './api'

type Device = {id:string;name:string;enabled:boolean;revision:number}
type Node = {id:string;name:string;enabled:boolean}
type Domain = {id:string;hostname:string;verified_at:number|null;txt_name:string;txt_value:string|null}
type Mapping = {id:string;device_id:string;node_id:string;domain_id:string|null;protocol:string;local_host:string;local_port:number;bind_port:number;enabled:boolean;revision:number}
type Runtime = {request:{request_id:string;state:string;updated_at:number}|null;worker_recent:boolean}
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
const pairing = ref('')
let pairTimer: ReturnType<typeof setTimeout>|undefined
const domainName = ref('')
const selectedMapping = ref<Mapping|null>(null)
const runtime = ref<Runtime|null>(null)
const deviceStatus = ref<Record<string,unknown>|null>(null)
const create = reactive({device_id:'',node_id:'',domain_id:'',protocol:'http',local_port:8080,bind_port:20000})
const nav = [{key:'dashboard',label:'仪表盘'},{key:'devices',label:'设备管理'},{key:'mappings',label:'映射管理'},{key:'domains',label:'域名管理'},{key:'nodes',label:'节点管理'}]
const title = computed(() => nav.find(n=>n.key===page.value)?.label)
const labels:Record<string,string> = {queued:'等待执行器',starting:'启动中',running:'已应用（执行器报告）',stopping:'停止中',stopped:'已停止',failed_or_unknown:'失败或未知'}
function clearPair(){pairing.value='';if(pairTimer) clearTimeout(pairTimer)}
function reset(){
  token.value='';user.value='';password.value='';devices.value=[];nodes.value=[];domains.value=[];mappings.value=[];
  selectedMapping.value=null;runtime.value=null;deviceStatus.value=null;clearPair();notice.value='';page.value='dashboard'
  Object.assign(create,{device_id:'',node_id:'',domain_id:'',protocol:'http',local_port:8080,bind_port:20000})
  domainName.value=''
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
  const [d,n,h,m]=await Promise.all([get<Device[]>('/devices'),get<Node[]>('/nodes'),get<Domain[]>('/domains'),get<Mapping[]>('/mappings')])
  devices.value=d;nodes.value=n;domains.value=h;mappings.value=m
  if(selectedMapping.value){
    selectedMapping.value=m.find(x=>x.id===selectedMapping.value?.id)||null
    runtime.value=selectedMapping.value?await get<Runtime>('/mappings/'+selectedMapping.value.id+'/runtime'):null
  }
}
async function login(){await run(async()=>{
  const s=await api<{access_token:string}>('/auth/login','','POST',{username:username.value,password:password.value})
  password.value='';token.value=s.access_token
  try{user.value=(await get<{username:string}>('/auth/me')).username;await refresh()}catch(e){reset();throw e}
})}
async function logout(){await run(async()=>{try{await send('/auth/logout','POST')}finally{reset()}})}
function go(key:string){page.value=key;clearPair();deviceStatus.value=null;selectedMapping.value=null;runtime.value=null;error.value='';notice.value=''}
async function issue(){await run(async()=>{clearPair();const p=await send<{pairing_code:string;expires_in:number}>('/devices/pairing-code','POST');pairing.value=p.pairing_code;pairTimer=setTimeout(clearPair,p.expires_in*1000)})}
async function revoke(d:Device){await run(async()=>{await send('/devices/'+d.id+'/revoke','POST');await refresh();deviceStatus.value=null;notice.value='设备凭据已吊销'})}
async function inspectDevice(d:Device){await run(async()=>{deviceStatus.value=await get('/devices/'+d.id+'/status')})}
async function addDomain(){await run(async()=>{await send('/domains','POST',{hostname:domainName.value});domainName.value='';await refresh();notice.value='域名草稿已创建'})}
async function verifyDomain(d:Domain){await run(async()=>{await send('/domains/verify','POST',{domain_id:d.id});await refresh();notice.value='DNS TXT 验证成功'})}
async function rotate(d:Domain){await run(async()=>{await send('/domains/'+d.id+'/challenge','POST');await refresh();notice.value='验证挑战已轮换'})}
async function addMapping(){await run(async()=>{
  await send('/mappings','POST',{...create,domain_id:create.protocol==='tcp'?null:create.domain_id})
  await refresh();notice.value='禁用映射草稿已创建'
})}
async function inspectMapping(m:Mapping){await run(async()=>{selectedMapping.value=m;runtime.value=null;runtime.value=await get('/mappings/'+m.id+'/runtime')})}
async function startMapping(){await run(async()=>{
  const m=selectedMapping.value;if(!m)return
  await send('/mappings/'+m.id+'/start','POST',{expected_revision:m.revision});runtime.value=await get('/mappings/'+m.id+'/runtime');notice.value='启动请求已提交，等待本地执行器'
})}
async function stopMapping(){await run(async()=>{
  const m=selectedMapping.value,r=runtime.value?.request;if(!m||!r)return
  await send('/mappings/'+m.id+'/stop','POST',{request_id:r.request_id});runtime.value=await get('/mappings/'+m.id+'/runtime');notice.value='停止请求已提交'
})}
const canStart=computed(()=>selectedMapping.value && !selectedMapping.value.enabled && selectedMapping.value.protocol!=='tcp' && runtime.value!==null && (!runtime.value.request||runtime.value.request.state==='stopped'||(runtime.value.request.state==='queued'&&runtime.value.request.updated_at<Math.floor(Date.now()/1000)-120)))
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
        <div class="heading"><div><h1>{{title}}</h1><p class="muted">真实管理 API · 当前页最多 100 条记录</p></div><a-button :loading="busy" @click="run(refresh)">刷新数据</a-button></div>
        <a-alert type="info" show-icon message="管理预览：映射草稿默认禁用，启动请求需本地执行器领取；设备心跳不等于真实隧道在线。"/>
        <a-alert v-if="error" type="error" show-icon :message="error"/>
        <a-alert v-if="notice" type="success" show-icon :message="notice"/>
        <template v-if="page==='dashboard'">
          <div class="metrics"><a-card v-for="s in [{label:'设备（当前页）',value:devices.length},{label:'映射草稿（当前页）',value:mappings.length},{label:'域名（当前页）',value:domains.length},{label:'节点（当前页）',value:nodes.length}]" :key="s.label"><a-statistic :title="s.label" :value="s.value"/></a-card></div>
          <a-card title="管理操作"><a-space wrap><a-button v-for="n in nav.slice(1)" :key="n.key" @click="go(n.key)">{{n.label}}</a-button></a-space><p class="muted">数据来自当前管理员实际可见记录，不是全局统计。</p></a-card>
        </template>
        <template v-if="page==='devices'">
          <a-card title="设备列表"><template #extra><a-button type="primary" :loading="busy" @click="issue">生成配对码</a-button></template>
            <a-alert v-if="pairing" type="warning" message="一次性配对码（10 分钟有效，请仅交给可信设备）"><template #description><code class="wrap-code" data-testid="pairing">{{pairing}}</code><a-button size="small" @click="clearPair">隐藏</a-button></template></a-alert>
            <a-table :data-source="devices" :pagination="{pageSize:10}" row-key="id" :scroll="{x:650}">
              <a-table-column title="设备名称" data-index="name"/><a-table-column title="版本" data-index="revision"/>
              <a-table-column title="凭据状态"><template #default="{record}"><a-tag :color="record.enabled?'green':'default'">{{record.enabled?'已启用':'已吊销'}}</a-tag></template></a-table-column>
              <a-table-column title="操作"><template #default="{record}"><a-space><a-button size="small" :disabled="busy" @click="inspectDevice(record)">管理状态</a-button><a-popconfirm title="永久吊销该设备凭据？" @confirm="revoke(record)"><a-button danger size="small" :disabled="busy||!record.enabled">吊销</a-button></a-popconfirm></a-space></template></a-table-column>
            </a-table>
            <a-card v-if="deviceStatus" size="small" title="设备心跳（自报）"><p>管理在线：{{deviceStatus.management_online?'是':'否'}}</p><p>期望版本：{{deviceStatus.desired_revision}} · 自报版本：{{deviceStatus.reported_revision??'—'}}</p><p>自报状态：{{deviceStatus.reported_state??'—'}}</p></a-card>
          </a-card>
        </template>
        <template v-if="page==='nodes'">
          <a-card title="共享节点目录"><p class="muted">只读；由本地操作员创建及维护。启用不代表已部署。</p><a-table :data-source="nodes" row-key="id" :pagination="{pageSize:10}"><a-table-column title="节点名称" data-index="name"/><a-table-column title="节点 ID" data-index="id"/><a-table-column title="状态"><template #default="{record}"><a-tag>{{record.enabled?'启用':'停用'}}</a-tag></template></a-table-column></a-table></a-card>
        </template>
        <template v-if="page==='domains'">
          <a-card title="添加域名"><form class="inline-form" @submit.prevent="addDomain"><a-input v-model:value="domainName" aria-label="域名" placeholder="web.example.com" required/><a-button type="primary" html-type="submit" :loading="busy">添加域名</a-button></form></a-card>
          <a-card title="域名列表"><a-table :data-source="domains" row-key="id" :pagination="{pageSize:10}" :scroll="{x:800}">
            <a-table-column title="域名" data-index="hostname"/><a-table-column title="最近验证"><template #default="{record}">{{time(record.verified_at)}}</template></a-table-column>
            <a-table-column title="TXT 证明"><template #default="{record}"><div class="wrap-code">{{record.txt_name}}<br>{{record.txt_value||'请轮换挑战'}}</div></template></a-table-column>
            <a-table-column title="操作"><template #default="{record}"><a-space><a-button size="small" :disabled="busy" @click="verifyDomain(record)">验证</a-button><a-popconfirm title="轮换会使旧验证失效，继续？" @confirm="rotate(record)"><a-button size="small" :disabled="busy">轮换</a-button></a-popconfirm></a-space></template></a-table-column>
          </a-table></a-card>
        </template>
        <template v-if="page==='mappings'">
          <a-card title="新建映射草稿"><form class="mapping-form" @submit.prevent="addMapping">
            <label>设备<a-select data-testid="mapping-device" v-model:value="create.device_id" aria-label="设备" :options="devices.filter(d=>d.enabled).map(d=>({value:d.id,label:d.name}))"/></label>
            <label>节点<a-select data-testid="mapping-node" v-model:value="create.node_id" aria-label="节点" :options="nodes.filter(n=>n.enabled).map(n=>({value:n.id,label:n.name}))"/></label>
            <label>协议<a-select v-model:value="create.protocol" aria-label="协议" :options="['http','https','tcp'].map(v=>({value:v,label:v.toUpperCase()}))"/></label>
            <label v-if="create.protocol!=='tcp'">域名<a-select data-testid="mapping-domain" v-model:value="create.domain_id" aria-label="映射域名" :options="domains.map(d=>({value:d.id,label:d.hostname}))"/></label>
            <label>本地端口<a-input-number v-model:value="create.local_port" :min="1" :max="65535"/></label>
            <label>中转端口<a-input-number v-model:value="create.bind_port" :min="20000" :max="29999"/></label>
            <a-button type="primary" html-type="submit" :loading="busy" :disabled="!create.device_id||!create.node_id||(create.protocol!=='tcp'&&!create.domain_id)">创建草稿</a-button>
          </form></a-card>
          <a-card title="映射列表"><a-table :data-source="mappings" row-key="id" :pagination="{pageSize:10}" :scroll="{x:750}">
            <a-table-column title="协议" data-index="protocol"/><a-table-column title="域名"><template #default="{record}">{{nameOf(domains,record.domain_id,'hostname')}}</template></a-table-column>
            <a-table-column title="本地端口" data-index="local_port"/><a-table-column title="中转端口" data-index="bind_port"/><a-table-column title="版本" data-index="revision"/>
            <a-table-column title="操作"><template #default="{record}"><a-button :disabled="busy" size="small" @click="inspectMapping(record)">运行详情</a-button></template></a-table-column>
          </a-table>
          <a-card v-if="selectedMapping" title="运行请求详情" size="small"><p>{{selectedMapping.id}}</p><p data-testid="runtime-state">{{runtime?labels[runtime.request?.state||'']||'尚无请求':'查询中'}}</p><p class="muted">执行器最近更新：{{runtime?.worker_recent?'是':'否'}}；不是实时业务探测。</p><a-space><a-button type="primary" :disabled="busy||!canStart" @click="startMapping">请求启动</a-button><a-button danger :disabled="busy||!canStop" @click="stopMapping">请求停止</a-button><a-button :disabled="busy" @click="inspectMapping(selectedMapping)">刷新状态</a-button></a-space></a-card></a-card>
        </template>
      </a-layout-content>
    </a-layout>
  </a-layout>
</template>

export class ApiError extends Error {
  constructor(public status: number) { super({
    400: '输入无效', 401: '登录失败或会话已过期', 404: '记录不存在或无权访问',
    409: '状态冲突，请刷新并检查版本、域名验证或执行器状态', 422: '请求格式无效',
    429: '请求过于频繁，请稍后重试', 503: '管理服务暂不可用',
  }[status] || '请求失败（' + status + '）') }
}
export async function api<T>(path: string, token = '', method = 'GET', body?: unknown): Promise<T> {
  if (!path.startsWith('/') || path.startsWith('//')) throw new Error('Invalid API path')
  const headers: Record<string,string> = {}
  if (token) headers.Authorization = 'Bearer ' + token
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const r = await fetch('/api/v1' + path, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    cache: 'no-store', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(12000),
  })
  if (!r.ok) throw new ApiError(r.status)
  return (r.status === 204 ? undefined : await r.json()) as T
}

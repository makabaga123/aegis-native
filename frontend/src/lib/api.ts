const BASE = '/api';

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${url}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `${res.status} ${res.statusText}`);
  }
  const ct = res.headers.get('content-type');
  if (ct?.includes('text/html')) return res.text() as T;
  return res.json();
}

// ── Scan ──
export function scanImage(image: string) {
  return request('/scan/image', { method: 'POST', body: JSON.stringify({ image }) });
}
export async function scanDockerfile(file: File) {
  const fd = new FormData(); fd.append('file', file);
  return request('/scan/dockerfile', { method: 'POST', body: fd, headers: {} });
}
export async function scanK8sYaml(file: File) {
  const fd = new FormData(); fd.append('file', file);
  return request('/scan/k8s-yaml', { method: 'POST', body: fd, headers: {} });
}

// ── Runtime ──
export function getRuntimeTimeline(limit = 200) {
  return request(`/runtime/timeline?limit=${limit}`);
}
export function postRuntimeEvent(event: unknown) {
  return request('/runtime/events', { method: 'POST', body: JSON.stringify(event) });
}
export function postRuntimeEvents(events: unknown[]) {
  return request('/runtime/events/batch', { method: 'POST', body: JSON.stringify(events) });
}

// ── Agent ──
export function analyzeSingle(req: Record<string, unknown>) {
  return request('/agent/analyze', { method: 'POST', body: JSON.stringify(req) });
}
export async function analyzeSingleFiles(fd: FormData) {
  return request('/agent/analyze-files', { method: 'POST', body: fd, headers: {} });
}

// ── Multi-Agent ──
export function analyzeMulti(req: Record<string, unknown>) {
  return request('/multi-agent/analyze', { method: 'POST', body: JSON.stringify(req) });
}
export async function analyzeMultiFiles(fd: FormData) {
  return request('/multi-agent/analyze-files', { method: 'POST', body: fd, headers: {} });
}

// ── MCP ──
export function listMcpTools() {
  return request('/mcp/tools');
}
export function callMcpTool(name: string, args: Record<string, unknown>) {
  return request('/mcp/call', { method: 'POST', body: JSON.stringify({ name, arguments: args }) });
}

// ── Reports ──
export function getFindings(limit = 200) {
  return request(`/report/findings?limit=${limit}`);
}
export function getTasks(limit = 100) {
  return request(`/report/tasks?limit=${limit}`);
}

// ── Health ──
export function healthCheck() {
  return request('/../health');
}

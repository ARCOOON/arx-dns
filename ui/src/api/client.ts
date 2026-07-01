const TOKEN_KEY = 'arx_token'
const LOGIN_PATH = '/login'

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

function handleUnauthorized(): void {
  clearToken()
  if (!window.location.pathname.startsWith(LOGIN_PATH)) {
    window.location.href = LOGIN_PATH
  }
}

export interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown
}

export async function apiRequest<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const headers = new Headers(options.headers)

  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json')
  }

  const token = getToken()
  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  let body: BodyInit | undefined
  if (options.body !== undefined) {
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json')
    }
    body = JSON.stringify(options.body)
  }

  const response = await fetch(path, {
    ...options,
    headers,
    body,
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new ApiError(401, 'Unauthorized')
  }

  if (!response.ok) {
    const message = await response.text()
    throw new ApiError(
      response.status,
      message || `Request failed with status ${response.status}`,
    )
  }

  if (response.status === 204) {
    return undefined as T
  }

  return (await response.json()) as T
}

export interface ZoneInfo {
  origin: string
  view: 'public' | 'internal'
  file_path: string
  records: number
}

export interface ZoneRecord {
  id: string
  name: string
  type: string
  ttl: string
  value: string
}

export interface ZonesListResponse {
  zones: ZoneInfo[]
}

export interface ZoneRecordsResponse {
  zone: string
  view: 'public' | 'internal'
  records: ZoneRecord[]
}

export interface CreateRecordPayload {
  name: string
  type: string
  ttl?: string | number
  value: string
  view?: 'public' | 'internal'
}

function zonePath(origin: string): string {
  const apex = origin.replace(/\.$/, '')
  return encodeURIComponent(apex)
}

export function fetchZones(): Promise<ZonesListResponse> {
  return apiRequest<ZonesListResponse>('/api/v1/zones')
}

export function createZone(
  name: string,
  view: 'public' | 'internal' = 'public',
): Promise<{ status: string; message: string; zone?: string }> {
  return apiRequest('/api/v1/zones', {
    method: 'POST',
    body: { name, view },
  })
}

export function deleteZone(
  origin: string,
  view: 'public' | 'internal' = 'public',
): Promise<{ status: string; message: string }> {
  const params = new URLSearchParams({ view })
  return apiRequest(
    `/api/v1/zones/${zonePath(origin)}?${params.toString()}`,
    { method: 'DELETE' },
  )
}

export function fetchZoneRecords(
  origin: string,
  view: 'public' | 'internal' = 'public',
): Promise<ZoneRecordsResponse> {
  const params = new URLSearchParams({ view })
  return apiRequest<ZoneRecordsResponse>(
    `/api/v1/zones/${zonePath(origin)}/records?${params.toString()}`,
  )
}

export function createZoneRecord(
  origin: string,
  payload: CreateRecordPayload,
): Promise<{ status: string; message: string }> {
  return apiRequest(`/api/v1/zones/${zonePath(origin)}/records`, {
    method: 'POST',
    body: payload,
  })
}

export function updateZoneRecord(
  origin: string,
  recordId: string,
  payload: CreateRecordPayload,
): Promise<{ status: string; message: string }> {
  return apiRequest(
    `/api/v1/zones/${zonePath(origin)}/records/${encodeURIComponent(recordId)}`,
    { method: 'PUT', body: payload },
  )
}

export function deleteZoneRecord(
  origin: string,
  recordId: string,
  view: 'public' | 'internal' = 'public',
): Promise<{ status: string; message: string }> {
  const params = new URLSearchParams({ view })
  return apiRequest(
    `/api/v1/zones/${zonePath(origin)}/records/${encodeURIComponent(recordId)}?${params.toString()}`,
    { method: 'DELETE' },
  )
}

export interface ZoneDNSSECStatus {
  enabled: boolean
  zone: string
  view: 'public' | 'internal'
  algorithm?: number
  ksk_tag?: number
  zsk_tag?: number
  ds?: string
}

export function fetchZoneDNSSEC(
  origin: string,
  view: 'public' | 'internal' = 'public',
): Promise<ZoneDNSSECStatus> {
  const params = new URLSearchParams({ view })
  return apiRequest<ZoneDNSSECStatus>(
    `/api/v1/zones/${zonePath(origin)}/dnssec?${params.toString()}`,
  )
}

export function enableZoneDNSSEC(
  origin: string,
  view: 'public' | 'internal' = 'public',
): Promise<ZoneDNSSECStatus> {
  return apiRequest<ZoneDNSSECStatus>(
    `/api/v1/zones/${zonePath(origin)}/dnssec/enable`,
    { method: 'POST', body: { view } },
  )
}

export function disableZoneDNSSEC(
  origin: string,
  view: 'public' | 'internal' = 'public',
): Promise<ZoneDNSSECStatus> {
  return apiRequest<ZoneDNSSECStatus>(
    `/api/v1/zones/${zonePath(origin)}/dnssec/disable`,
    { method: 'POST', body: { view } },
  )
}

export interface ZoneACLConfig {
  allow_query?: string[]
  allow_recursion?: string[]
  allow_transfer?: string[]
}

export interface ACLConfig {
  match_lists: Record<string, string[]>
  allow_query: string[]
  allow_recursion: string[]
  allow_transfer: string[]
  zones?: Record<string, ZoneACLConfig>
}

export interface ACLConfigUpdateResponse {
  success: boolean
  requires_restart: boolean
}

export function fetchACLConfig(): Promise<ACLConfig> {
  return apiRequest<ACLConfig>('/api/v1/config/acl')
}

export function updateACLConfig(config: ACLConfig): Promise<ACLConfigUpdateResponse> {
  return apiRequest<ACLConfigUpdateResponse>('/api/v1/config/acl', {
    method: 'PUT',
    body: config,
  })
}

export type RPZAction = 'NXDOMAIN' | 'NODATA' | 'DROP' | 'CNAME' | 'A' | 'AAAA'

export interface RPZPolicy {
  domain: string
  action: RPZAction
  target?: string
}

export interface RPZConfig {
  enabled: boolean
  policies: RPZPolicy[]
}

export interface RPZConfigUpdateResponse {
  success: boolean
  requires_restart: boolean
}

export function fetchRPZConfig(): Promise<RPZConfig> {
  return apiRequest<RPZConfig>('/api/v1/config/rpz')
}

export function updateRPZConfig(config: RPZConfig): Promise<RPZConfigUpdateResponse> {
  return apiRequest<RPZConfigUpdateResponse>('/api/v1/config/rpz', {
    method: 'PUT',
    body: config,
  })
}

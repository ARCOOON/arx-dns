import { apiRequest } from '@/api/client'

export interface ServerConfig {
  listen: string
  port: number
  event_loops: number
  log_level: string
}

export interface TLSConfig {
  cert_file: string
  key_file: string
}

export interface ListenersConfig {
  dot: string
  doh: string
}

export interface APIConfig {
  listen: string
  auth_token: string
  tls_cert: string
  tls_key: string
}

export interface ZonesConfig {
  directory: string
}

export interface RecursiveConfig {
  upstreams: string[]
  trusted_subnets: string[]
}

export interface ResolverConfig {
  mode: string
  qname_minimization: boolean
  root_hints_file: string
  auto_update_root_hints: boolean
}

export interface FirewallConfig {
  blocklists_directory: string
  block_action: string
}

export interface RateLimitConfig {
  enabled: boolean
  requests_per_second: number
  burst: number
}

export interface LoggingConfig {
  file_path: string
  max_size_mb: number
  max_backups: number
  max_age_days: number
}

export interface ECSConfig {
  enabled: boolean
  ipv4_prefix_length: number
  ipv6_prefix_length: number
}

export interface SecurityConfig {
  dnssec_validation: boolean
  dns_cookies_enabled: boolean
  dns_cookie_secret?: string
  root_anchors: string[]
}

export interface UpdateConfig {
  keys: Record<string, string>
}

export interface XFRConfig {
  enabled: boolean
  allowed_subnets: string[]
  notify_slaves: string[]
}

export interface ZoneACLConfig {
  allow_query?: string[]
  allow_recursion?: string[]
  allow_transfer?: string[]
}

export interface ACLSectionConfig {
  lists?: Record<string, string[]>
  allow_query?: string[]
  allow_recursion?: string[]
  allow_transfer?: string[]
  zones?: Record<string, ZoneACLConfig>
}

export interface AppConfig {
  server: ServerConfig
  tls: TLSConfig
  listeners: ListenersConfig
  api: APIConfig
  zones: ZonesConfig
  recursive: RecursiveConfig
  resolver: ResolverConfig
  firewall: FirewallConfig
  rate_limit: RateLimitConfig
  logging: LoggingConfig
  ecs: ECSConfig
  security: SecurityConfig
  update: UpdateConfig
  xfr: XFRConfig
  acl?: ACLSectionConfig
}

export interface ConfigUpdateResponse {
  success: boolean
  requires_restart: boolean
}

/** Deep-clones config for PUT payloads; safe for Vue reactive proxies. */
export function cloneAppConfig(config: AppConfig): AppConfig {
  return JSON.parse(JSON.stringify(config)) as AppConfig
}

export function fetchConfig(): Promise<AppConfig> {
  return apiRequest<AppConfig>('/api/v1/config')
}

export function updateConfig(config: AppConfig): Promise<ConfigUpdateResponse> {
  return apiRequest<ConfigUpdateResponse>('/api/v1/config', {
    method: 'PUT',
    body: config,
  })
}

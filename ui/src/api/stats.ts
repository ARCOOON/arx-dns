import { apiRequest } from '@/api/client'

export interface StatsSnapshot {
  total_queries: number
  udp_queries: number
  tcp_queries: number
  dot_queries: number
  doh_queries: number
  dropped_packets: number
  parse_errors: number
  write_errors: number
  refused_answers: number
  authoritative_answers: number
  nxdomain_answers: number
  forwarded_queries: number
  local_queries: number
  upstream_queries: number
  upstream_failures: number
  cache_hits: number
  cache_misses: number
  negative_cache_hits: number
  acl_rejected: number
  truncated_responses: number
  tcp_timeouts: number
  firewall_blocked: number
  dnssec_validations_passed: number
  dnssec_validations_failed: number
  rrl_dropped: number
  cookies_verified: number
  cookies_rejected: number
  ecs_queries_forwarded: number
  xfr_completed: number
  xfr_refused: number
  notify_sent: number
  notify_failed: number
  qname_min_fallbacks: number
  rtt_tracked_ips: number
}

export function fetchStats(): Promise<StatsSnapshot> {
  return apiRequest<StatsSnapshot>('/api/v1/stats')
}

export interface StatsHistoryPoint {
  timestamp: string
  queries: number
  cache_hits: number
  dropped: number
  dnssec_fails: number
  local_queries: number
  upstream_queries: number
}

export interface StatsHistoryResponse {
  window: string
  granularity: string
  points: StatsHistoryPoint[]
}

export function getStatsHistory(range: string): Promise<StatsHistoryResponse> {
  const params = new URLSearchParams({ range })
  return apiRequest<StatsHistoryResponse>(`/api/v1/stats/history?${params.toString()}`)
}

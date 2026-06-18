import { apiRequest } from '@/api/client'

export interface BlocklistSource {
  id: number
  url: string
  enabled: boolean
}

export interface BlocklistSourcesResponse {
  sources: BlocklistSource[]
}

export interface FirewallStatusResponse {
  blocked_domains_count: number
}

export interface BlocklistMutationResponse {
  status: string
  message: string
  source?: BlocklistSource
}

export function fetchFirewallStatus(): Promise<FirewallStatusResponse> {
  return apiRequest<FirewallStatusResponse>('/api/v1/firewall/status')
}

export function fetchBlocklistSources(): Promise<BlocklistSourcesResponse> {
  return apiRequest<BlocklistSourcesResponse>('/api/v1/firewall/sources')
}

export function createBlocklistSource(url: string): Promise<BlocklistMutationResponse> {
  return apiRequest<BlocklistMutationResponse>('/api/v1/firewall/sources', {
    method: 'POST',
    body: { url },
  })
}

export function deleteBlocklistSource(id: number): Promise<BlocklistMutationResponse> {
  return apiRequest<BlocklistMutationResponse>(`/api/v1/firewall/sources/${id}`, {
    method: 'DELETE',
  })
}

export function syncBlocklists(): Promise<BlocklistMutationResponse> {
  return apiRequest<BlocklistMutationResponse>('/api/v1/firewall/sync', {
    method: 'POST',
  })
}

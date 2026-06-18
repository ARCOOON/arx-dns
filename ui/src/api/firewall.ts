import { apiRequest } from '@/api/client'

export interface BlocklistSource {
  id: number
  url: string
  description?: string
  enabled: boolean
  last_count: number
  last_sync?: string
}

export interface CustomBlocklistEntry {
  id: number
  domain: string
  created_at: string
}

export interface BlocklistSourcesResponse {
  sources: BlocklistSource[]
}

export interface CustomBlocklistResponse {
  domains: CustomBlocklistEntry[]
}

export interface FirewallStatusResponse {
  blocked_domains_count: number
}

export interface BlocklistMutationResponse {
  status: string
  message: string
  source?: BlocklistSource
  entry?: CustomBlocklistEntry
}

export function fetchFirewallStatus(): Promise<FirewallStatusResponse> {
  return apiRequest<FirewallStatusResponse>('/api/v1/firewall/status')
}

export function fetchBlocklistSources(): Promise<BlocklistSourcesResponse> {
  return apiRequest<BlocklistSourcesResponse>('/api/v1/firewall/sources')
}

export function createBlocklistSource(
  url: string,
  description?: string,
): Promise<BlocklistMutationResponse> {
  return apiRequest<BlocklistMutationResponse>('/api/v1/firewall/sources', {
    method: 'POST',
    body: { url, description: description?.trim() || undefined },
  })
}

export function updateBlocklistSource(
  id: number,
  patch: { enabled?: boolean; description?: string },
): Promise<BlocklistMutationResponse> {
  return apiRequest<BlocklistMutationResponse>(`/api/v1/firewall/sources/${id}`, {
    method: 'PATCH',
    body: patch,
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

export function fetchCustomBlocklist(): Promise<CustomBlocklistResponse> {
  return apiRequest<CustomBlocklistResponse>('/api/v1/firewall/custom')
}

export function createCustomBlocklistDomain(domain: string): Promise<BlocklistMutationResponse> {
  return apiRequest<BlocklistMutationResponse>('/api/v1/firewall/custom', {
    method: 'POST',
    body: { domain },
  })
}

export function deleteCustomBlocklistDomain(id: number): Promise<BlocklistMutationResponse> {
  return apiRequest<BlocklistMutationResponse>(`/api/v1/firewall/custom/${id}`, {
    method: 'DELETE',
  })
}

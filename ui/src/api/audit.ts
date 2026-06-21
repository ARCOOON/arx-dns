import { apiRequest } from '@/api/client'

export interface AuditLogEntry {
  id: number
  timestamp: string
  client_ip: string
  action: string
  target?: string
  details?: string
}

export interface AuditLogsResponse {
  logs: AuditLogEntry[]
}

export function fetchAuditLogs(limit = 500): Promise<AuditLogsResponse> {
  return apiRequest<AuditLogsResponse>(`/api/v1/audit?limit=${limit}`)
}

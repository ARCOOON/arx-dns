import { apiRequest } from '@/api/client'

export interface LogRotationConfig {
  file_path: string
  max_size_mb: number
  max_backups: number
  max_age_days: number
}

export interface LogsConfig {
  level: string
  rotation: LogRotationConfig
}

export interface LogsHistoryResponse {
  lines: string[]
}

export function fetchLogsHistory(): Promise<LogsHistoryResponse> {
  return apiRequest<LogsHistoryResponse>('/api/v1/logs/history')
}

export function fetchLogsConfig(): Promise<LogsConfig> {
  return apiRequest<LogsConfig>('/api/v1/logs/config')
}

export function updateLogsConfig(config: LogsConfig): Promise<LogsConfig> {
  return apiRequest<LogsConfig>('/api/v1/logs/config', {
    method: 'PUT',
    body: config,
  })
}

export function openLogsEventSource(): EventSource {
  const token = localStorage.getItem('arx_token')
  const query = token ? `?token=${encodeURIComponent(token)}` : ''
  return new EventSource(`/api/v1/logs/stream${query}`)
}

export type LogLevelFilter = 'ALL' | 'DEBUG' | 'INFO' | 'WARN' | 'ERROR'

const levelRank: Record<Exclude<LogLevelFilter, 'ALL'>, number> = {
  DEBUG: 10,
  INFO: 20,
  WARN: 30,
  ERROR: 40,
}

export interface ParsedLogLine {
  raw: string
  level: string
  message: string
  time: string
  attrs: string
}

export function parseLogLine(raw: string): ParsedLogLine {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>
    const reserved = new Set(['level', 'msg', 'time'])
    const attrParts: string[] = []
    for (const [key, value] of Object.entries(parsed)) {
      if (reserved.has(key)) {
        continue
      }
      if (value === null || value === undefined) {
        continue
      }
      attrParts.push(`${key}=${formatAttrValue(value)}`)
    }
    return {
      raw,
      level: String(parsed.level ?? 'INFO').toUpperCase(),
      message: String(parsed.msg ?? raw),
      time: String(parsed.time ?? ''),
      attrs: attrParts.join(' '),
    }
  } catch {
    return {
      raw,
      level: 'INFO',
      message: raw,
      time: '',
      attrs: '',
    }
  }
}

function formatAttrValue(value: unknown): string {
  if (typeof value === 'string') {
    return value
  }
  return JSON.stringify(value)
}

export function shouldDisplayLevel(
  lineLevel: string,
  filter: LogLevelFilter,
): boolean {
  if (filter === 'ALL') {
    return true
  }
  const normalized = lineLevel.toUpperCase() as Exclude<LogLevelFilter, 'ALL'>
  const lineRank = levelRank[normalized] ?? levelRank.INFO
  const filterRank = levelRank[filter]
  return lineRank >= filterRank
}

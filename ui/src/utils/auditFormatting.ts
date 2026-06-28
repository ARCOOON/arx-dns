export interface ParsedAuditDetails {
  method?: string
  path?: string
  status?: number
  success?: boolean
  type?: string
}

export interface FormattedAuditEntry {
  label: string
  details: ParsedAuditDetails
}

const ACTION_LABELS: Record<string, string> = {
  create_record: 'Create Record',
  update_record: 'Update Record',
  delete_record: 'Delete Record',
  create_zone: 'Create Zone',
  delete_zone: 'Delete Zone',
  reload_zones: 'Reload Zones',
  enable_dnssec: 'Enable DNSSEC',
  disable_dnssec: 'Disable DNSSEC',
  sync_blocklists: 'Sync Blocklists',
  create_blocklist_source: 'Create Blocklist Source',
  update_blocklist_source: 'Update Blocklist Source',
  delete_blocklist_source: 'Delete Blocklist Source',
  create_acl_rule: 'Create ACL Rule',
  update_acl_rule: 'Update ACL Rule',
  delete_acl_rule: 'Delete ACL Rule',
  update_config: 'Update Config',
  update_log_config: 'Update Log Config',
}

function titleCaseAction(action: string): string {
  return action
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ')
}

export function parseAuditDetails(raw?: string): ParsedAuditDetails {
  const parsed: ParsedAuditDetails = {}
  if (!raw) {
    return parsed
  }

  for (const part of raw.split(/\s+/)) {
    const separator = part.indexOf('=')
    if (separator <= 0) {
      continue
    }

    const key = part.slice(0, separator)
    const value = part.slice(separator + 1)

    switch (key) {
      case 'method':
        parsed.method = value
        break
      case 'path':
        parsed.path = value
        break
      case 'status': {
        const status = Number.parseInt(value, 10)
        if (!Number.isNaN(status)) {
          parsed.status = status
        }
        break
      }
      case 'success':
        parsed.success = value === 'true'
        break
      case 'type':
        parsed.type = value
        break
    }
  }

  return parsed
}

export function formatAuditAction(action: string, details?: string): FormattedAuditEntry {
  const parsed = parseAuditDetails(details)
  const base = ACTION_LABELS[action] ?? titleCaseAction(action)
  const recordType = parsed.type?.trim()

  let label = base
  if (recordType && (action === 'create_record' || action === 'update_record')) {
    label = `${base} (${recordType})`
  }

  return { label, details: parsed }
}

export function auditDetailRows(
  details: ParsedAuditDetails,
): Array<{ key: string; value: string }> {
  const rows: Array<{ key: string; value: string }> = []

  if (details.method) {
    rows.push({ key: 'Method', value: details.method })
  }
  if (details.path) {
    rows.push({ key: 'Path', value: details.path })
  }
  if (details.status !== undefined) {
    rows.push({ key: 'Status', value: String(details.status) })
  }
  if (details.success !== undefined) {
    rows.push({ key: 'Success', value: details.success ? 'true' : 'false' })
  }
  if (details.type) {
    rows.push({ key: 'Type', value: details.type })
  }

  return rows
}

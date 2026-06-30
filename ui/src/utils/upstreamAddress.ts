/**
 * Normalizes an upstream resolver address for API storage.
 * Strips implicit port 53; preserves custom ports and IPv6 bracket form when required.
 */
export function normalizeUpstreamAddress(raw: string): string {
  const trimmed = raw.trim()
  if (!trimmed) {
    return ''
  }

  const bracketMatch = trimmed.match(/^\[(.+)]:(\d+)$/)
  if (bracketMatch) {
    const port = bracketMatch[2]
    const host = bracketMatch[1]
    return port === '53' ? host : trimmed
  }

  const lastColon = trimmed.lastIndexOf(':')
  if (lastColon > -1 && trimmed.indexOf(':') === lastColon) {
    const host = trimmed.slice(0, lastColon)
    const port = trimmed.slice(lastColon + 1)
    if (/^\d+$/.test(port)) {
      return port === '53' ? host : trimmed
    }
  }

  return trimmed
}

export function normalizeUpstreamList(values: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const value of values) {
    const normalized = normalizeUpstreamAddress(value)
    if (!normalized || seen.has(normalized)) {
      continue
    }
    seen.add(normalized)
    out.push(normalized)
  }
  return out
}

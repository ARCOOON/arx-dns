import { ApiError } from '@/api/client'

export function parseApiError(err: unknown, fallback: string): string {
  if (!(err instanceof ApiError)) {
    return fallback
  }
  try {
    const parsed = JSON.parse(err.message) as { error?: string }
    if (parsed.error) {
      return parsed.error
    }
  } catch {
    // Use raw message when the body is not JSON.
  }
  return err.message || fallback
}

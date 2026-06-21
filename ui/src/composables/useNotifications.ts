import { reactive } from 'vue'
import { toast } from 'vue-sonner'

export type NotificationType = 'success' | 'error'

export interface NotificationEntry {
  id: number
  message: string
  type: NotificationType
  timestamp: Date
}

const MAX_HISTORY = 50
let nextId = 1

export const history = reactive<NotificationEntry[]>([])

export function notify(message: string, type: NotificationType = 'success'): void {
  if (type === 'success') {
    toast.success(message)
  } else {
    toast.error(message)
  }

  history.unshift({
    id: nextId++,
    message,
    type,
    timestamp: new Date(),
  })

  if (history.length > MAX_HISTORY) {
    history.splice(MAX_HISTORY)
  }
}

export function clearNotificationHistory(): void {
  history.splice(0)
}

import { useStorage } from '@vueuse/core'

export type ToastPosition =
  | 'top-right'
  | 'bottom-right'
  | 'bottom-left'
  | 'top-left'

export const TOAST_POSITION_OPTIONS: ToastPosition[] = [
  'top-right',
  'bottom-right',
  'bottom-left',
  'top-left',
]

export function useToastPosition() {
  return useStorage<ToastPosition>('arx-ui-toast-position', 'bottom-right')
}

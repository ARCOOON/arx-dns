import { useStorage } from '@vueuse/core'

export type ToastPosition =
  | 'top-right'
  | 'bottom-right'
  | 'bottom-left'
  | 'top-left'

export const TOAST_POSITION_OPTIONS: { value: ToastPosition; label: string }[] = [
  { value: 'top-right', label: 'Top Right' },
  { value: 'bottom-right', label: 'Bottom Right' },
  { value: 'bottom-left', label: 'Bottom Left' },
  { value: 'top-left', label: 'Top Left' },
]

export function useToastPosition() {
  return useStorage<ToastPosition>('arx-ui-toast-position', 'bottom-right')
}

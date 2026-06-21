<script setup lang="ts">
import { computed } from 'vue'
import { Bell, CheckCircle2, XCircle } from 'lucide-vue-next'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  clearNotificationHistory,
  history,
  type NotificationType,
} from '@/composables/useNotifications'
import { useToastPosition, type ToastPosition } from '@/composables/useToastPosition'
import { cn } from '@/lib/utils'

const toastPosition = useToastPosition()

const fabPositionClass = computed(() => {
  const map: Record<ToastPosition, string> = {
    'bottom-right': 'bottom-6 right-6',
    'bottom-left': 'bottom-6 left-6',
    'top-right': 'top-6 right-6',
    'top-left': 'top-6 left-6',
  }
  return map[toastPosition.value]
})

const popoverSide = computed(() =>
  toastPosition.value.startsWith('top') ? 'bottom' : 'top',
)

const popoverAlign = computed(() =>
  toastPosition.value.endsWith('right') ? 'end' : 'start',
)

function formatTimestamp(date: Date): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'short',
    timeStyle: 'medium',
  }).format(date)
}

function typeIcon(type: NotificationType) {
  return type === 'success' ? CheckCircle2 : XCircle
}

function typeClass(type: NotificationType): string {
  return type === 'success'
    ? 'text-emerald-600 dark:text-emerald-400'
    : 'text-destructive'
}
</script>

<template>
  <div :class="cn('pointer-events-none fixed z-50', fabPositionClass)">
    <Popover>
      <PopoverTrigger as-child>
        <Button
          size="icon"
          class="pointer-events-auto relative size-12 rounded-full shadow-md"
          aria-label="Open notification history"
        >
          <Bell class="size-5" />
          <span
            v-if="history.length > 0"
            class="absolute -right-0.5 -top-0.5 flex size-5 items-center justify-center rounded-full bg-primary text-[10px] font-medium text-primary-foreground"
          >
            {{ history.length > 9 ? '9+' : history.length }}
          </span>
        </Button>
      </PopoverTrigger>

      <PopoverContent
        :side="popoverSide"
        :align="popoverAlign"
        :side-offset="12"
        class="pointer-events-auto w-80 p-0"
      >
        <div class="flex items-center justify-between border-b px-4 py-3">
          <p class="text-sm font-medium">Notification History</p>
          <Button
            variant="ghost"
            size="sm"
            class="h-7 text-xs"
            :disabled="history.length === 0"
            @click="clearNotificationHistory"
          >
            Clear History
          </Button>
        </div>

        <div v-if="history.length === 0" class="px-4 py-8 text-center text-sm text-muted-foreground">
          No notifications yet.
        </div>

        <ul v-else class="max-h-80 overflow-y-auto">
          <li
            v-for="entry in history"
            :key="entry.id"
            class="flex gap-3 border-b px-4 py-3 last:border-b-0"
          >
            <component
              :is="typeIcon(entry.type)"
              class="mt-0.5 size-4 shrink-0"
              :class="typeClass(entry.type)"
              aria-hidden="true"
            />
            <div class="min-w-0 flex-1">
              <p class="text-sm leading-snug">{{ entry.message }}</p>
              <p class="mt-1 text-xs text-muted-foreground">
                {{ formatTimestamp(entry.timestamp) }}
              </p>
            </div>
          </li>
        </ul>
      </PopoverContent>
    </Popover>
  </div>
</template>

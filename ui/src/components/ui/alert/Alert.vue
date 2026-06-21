<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  class?: HTMLAttributes['class']
  variant?: 'default' | 'destructive'
}>()
</script>

<template>
  <div
    role="alert"
    :class="
      cn(
        'relative w-full rounded-lg border px-4 py-3 text-sm',
        props.variant === 'destructive'
          ? 'border-destructive/50 bg-destructive/10 text-destructive'
          : 'border-border bg-muted/50 text-foreground',
        props.class,
      )
    "
  >
    <slot />
  </div>
</template>

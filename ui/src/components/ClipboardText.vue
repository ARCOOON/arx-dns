<script setup lang="ts">
import { ref } from 'vue'
import { Check, Copy } from 'lucide-vue-next'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

const props = withDefaults(
  defineProps<{
    value: string
    label?: string
    class?: string
  }>(),
  {
    label: 'Copy',
  },
)

const copied = ref(false)
let resetTimer: ReturnType<typeof setTimeout> | undefined

async function copyToClipboard(): Promise<void> {
  const text = props.value.trim()
  if (!text) {
    return
  }
  try {
    await navigator.clipboard.writeText(text)
    copied.value = true
    if (resetTimer) {
      clearTimeout(resetTimer)
    }
    resetTimer = setTimeout(() => {
      copied.value = false
    }, 2000)
  } catch {
    copied.value = false
  }
}
</script>

<template>
  <div :class="cn('flex items-start gap-2', props.class)">
    <code class="min-w-0 flex-1 break-all rounded-md bg-muted px-2 py-1.5 font-mono text-xs">
      {{ value }}
    </code>
    <Button
      type="button"
      variant="outline"
      size="sm"
      class="shrink-0"
      :disabled="!value.trim()"
      :aria-label="copied ? 'Copied' : label"
      @click="copyToClipboard"
    >
      <Check v-if="copied" class="size-4 text-emerald-600" />
      <Copy v-else class="size-4" />
      <span class="sr-only">{{ copied ? 'Copied' : label }}</span>
    </Button>
  </div>
</template>

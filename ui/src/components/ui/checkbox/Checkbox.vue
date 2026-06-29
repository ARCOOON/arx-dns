<script setup lang="ts">
import type { CheckboxRootEmits, CheckboxRootProps } from 'radix-vue'
import type { HTMLAttributes } from 'vue'
import { CheckboxIndicator, CheckboxRoot } from 'radix-vue'
import { Check } from 'lucide-vue-next'
import { cn } from '@/lib/utils'

const props = defineProps<CheckboxRootProps & { class?: HTMLAttributes['class'] }>()
const emits = defineEmits<CheckboxRootEmits>()
</script>

<template>
  <CheckboxRoot v-bind="props" :class="cn(
    'peer size-4 shrink-0 rounded-sm border border-primary shadow focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-primary data-[state=checked]:text-primary-foreground',
    props.class,
  )
    " @update:checked="emits('update:checked', $event)">
    <CheckboxIndicator class="flex items-center justify-center text-current">
      <Check class="size-3.5" />
    </CheckboxIndicator>
  </CheckboxRoot>
</template>
